export const dynamic = "force-dynamic";
export const runtime = "nodejs";

import { NextResponse } from "next/server";
import { auditLog } from "@/lib/api/audit";
import { withApiHardening } from "@/lib/api/hardening";
import { verifyAdminAuth } from "@/lib/auth/adminAuth";
import { getDb } from "@/lib/mongodb";
import { ObjectId } from "mongodb";
import { invalidateMarketplaceCache } from "@/lib/cache/redis";

export async function POST(request, context) {
  return withApiHardening(
    request,
    { route: "admin/materials/flag", rateLimit: { limit: 60, windowMs: 60_000 } },
    async () => {
      try {
        const auth = await verifyAdminAuth(request);
        if (!auth.authorized) {
          auditLog({ event: "admin_unauthorized", route: "admin/materials/flag", method: "POST", status: auth.status || 403 });
          return NextResponse.json({ error: auth.error || "Forbidden: Admin access required" }, { status: auth.status || 403 });
        }

        const params = await Promise.resolve(context?.params);
        const materialId = params?.id;

        if (!materialId || !ObjectId.isValid(materialId)) {
          return NextResponse.json({ error: "Invalid material ID" }, { status: 400 });
        }

        let body = {};
        try {
          body = await request.json();
        } catch {
          body = {};
        }

        const reason = body?.reason || body?.notes || "Flagged for administrative moderation review";
        const db = await getDb();

        const material = await db.collection("materials").findOne({ _id: new ObjectId(materialId) });
        if (!material) {
          return NextResponse.json({ error: "Material not found" }, { status: 404 });
        }

        const now = new Date();
        const adminActor = auth.user.walletAddress || auth.user.sub || "admin";

        await db.collection("materials").updateOne(
          { _id: new ObjectId(materialId) },
          {
            $set: {
              flagged: true,
              flagReason: reason,
              flaggedAt: now,
              flaggedBy: adminActor,
              updatedAt: now,
            },
          }
        );

        // Record in admin audit trail
        const auditEntry = {
          event: "material_flagged",
          materialId,
          title: material.title || material.name || null,
          adminActor,
          reason,
          timestamp: now,
        };
        await db.collection("admin_audit_trail").insertOne(auditEntry);

        auditLog({
          event: "material_flagged",
          route: "admin/materials/flag",
          method: "POST",
          status: 200,
          actor: adminActor,
          materialId,
        });

        await invalidateMarketplaceCache();

        return NextResponse.json({
          success: true,
          message: "Material flagged for moderation review",
          materialId,
          flagged: true,
          flagReason: reason,
        });
      } catch (err) {
        auditLog({
          event: "admin_flag_failed",
          route: "admin/materials/flag",
          method: "POST",
          status: 500,
          reason: err.message,
        });
        return NextResponse.json({ error: "Server error" }, { status: 500 });
      }
    }
  );
}
