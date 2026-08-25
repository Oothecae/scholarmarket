export const dynamic = "force-dynamic";
export const runtime = "nodejs";

import { NextResponse } from "next/server";
import { auditLog } from "@/lib/api/audit";
import { withApiHardening } from "@/lib/api/hardening";
import { verifyAdminAuth } from "@/lib/auth/adminAuth";
import { getDb } from "@/lib/mongodb";
import { ObjectId } from "mongodb";
import { pinata } from "@/lib/pinata";
import { invalidateMarketplaceCache } from "@/lib/cache/redis";

export async function DELETE(request, context) {
  return withApiHardening(
    request,
    { route: "admin/materials/delete", rateLimit: { limit: 60, windowMs: 60_000 } },
    async () => {
      try {
        const auth = await verifyAdminAuth(request);
        if (!auth.authorized) {
          auditLog({ event: "admin_unauthorized", route: "admin/materials/delete", method: "DELETE", status: auth.status || 403 });
          return NextResponse.json({ error: auth.error || "Forbidden: Admin access required" }, { status: auth.status || 403 });
        }

        const params = await Promise.resolve(context?.params);
        const materialId = params?.id;

        if (!materialId || !ObjectId.isValid(materialId)) {
          return NextResponse.json({ error: "Invalid material ID" }, { status: 400 });
        }

        const db = await getDb();
        const material = await db.collection("materials").findOne({ _id: new ObjectId(materialId) });
        if (!material) {
          return NextResponse.json({ error: "Material not found" }, { status: 404 });
        }

        const adminActor = auth.user.walletAddress || auth.user.sub || "admin";
        const cidsToUnpin = [];

        if (material.storageKey) cidsToUnpin.push(material.storageKey);
        if (material.fileCid && material.fileCid !== material.storageKey) cidsToUnpin.push(material.fileCid);
        if (material.thumbnailCid) cidsToUnpin.push(material.thumbnailCid);

        const unpinResults = [];
        for (const cid of cidsToUnpin) {
          try {
            if (pinata && typeof pinata.unpin === "function") {
              await pinata.unpin([cid]);
              unpinResults.push({ cid, status: "unpinned" });
            } else if (pinata && pinata.files && typeof pinata.files.delete === "function") {
              await pinata.files.delete([cid]);
              unpinResults.push({ cid, status: "unpinned" });
            } else if (pinata && pinata.files && pinata.files.public && typeof pinata.files.public.delete === "function") {
              await pinata.files.public.delete([cid]);
              unpinResults.push({ cid, status: "unpinned" });
            }
          } catch (unpinErr) {
            console.warn(`[Pinata] Failed to unpin CID ${cid}:`, unpinErr.message);
            unpinResults.push({ cid, status: "unpin_failed", error: unpinErr.message });
          }
        }

        // Delete from materials collection
        await db.collection("materials").deleteOne({ _id: new ObjectId(materialId) });

        // Clean up any pending pins or side effects
        try {
          await db.collection("pending_pins").deleteMany({ materialId });
        } catch {
          // ignore
        }

        const now = new Date();
        const auditEntry = {
          event: "material_force_deleted",
          materialId,
          title: material.title || material.name || null,
          userAddress: material.userAddress || null,
          adminActor,
          unpinnedCids: cidsToUnpin,
          unpinResults,
          timestamp: now,
        };
        await db.collection("admin_audit_trail").insertOne(auditEntry);

        auditLog({
          event: "material_force_deleted",
          route: "admin/materials/delete",
          method: "DELETE",
          status: 200,
          actor: adminActor,
          materialId,
        });

        await invalidateMarketplaceCache();

        return NextResponse.json({
          success: true,
          message: "Material deleted successfully and unpinned from IPFS",
          materialId,
          unpinnedCids: cidsToUnpin,
        });
      } catch (err) {
        auditLog({
          event: "admin_delete_failed",
          route: "admin/materials/delete",
          method: "DELETE",
          status: 500,
          reason: err.message,
        });
        return NextResponse.json({ error: "Server error" }, { status: 500 });
      }
    }
  );
}
