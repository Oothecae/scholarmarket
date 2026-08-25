import test from "node:test";
import assert from "node:assert/strict";
import {
  validateFileMagicNumber,
  validateUploadedFile,
  validateFileSize,
  MAX_FILE_SIZE_BYTES,
  MAX_THUMBNAIL_SIZE_BYTES,
} from "../../src/lib/ipfs/uploadValidator.js";

// Helper to create mock Web File
function createMockFile(bytes, type, name = "test.dat", size = null) {
  const u8 = new Uint8Array(bytes);
  const totalSize = size !== null ? size : u8.length;
  return {
    name,
    type,
    size: totalSize,
    arrayBuffer: async () => u8.buffer,
    slice: (start, end) => ({
      arrayBuffer: async () => u8.slice(start, end).buffer,
    }),
  };
}

test("Upload Validator — Magic bytes validation", async (t) => {
  await t.test("accepts valid PDF magic bytes (%PDF)", async () => {
    const pdfBytes = [0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34];
    const file = createMockFile(pdfBytes, "application/pdf", "sample.pdf");
    const result = await validateFileMagicNumber(file);
    assert.equal(result.valid, true);
  });

  await t.test("rejects spoofed PDF with invalid magic bytes", async () => {
    const fakeBytes = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    const file = createMockFile(fakeBytes, "application/pdf", "fake.pdf");
    const result = await validateFileMagicNumber(file);
    assert.equal(result.valid, false);
    assert.match(result.reason, /does not match declared MIME type/i);
  });

  await t.test("accepts valid MP4 video header (ftyp at offset 4)", async () => {
    // Offset 0-3: size, Offset 4-7: "ftyp" (0x66, 0x74, 0x79, 0x70)
    const mp4Bytes = [0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x6d, 0x70, 0x34, 0x32];
    const file = createMockFile(mp4Bytes, "video/mp4", "lecture.mp4");
    const result = await validateFileMagicNumber(file);
    assert.equal(result.valid, true);
  });

  await t.test("rejects fake MP4 without ftyp header", async () => {
    const fakeMp4 = [0x00, 0x00, 0x00, 0x18, 0x4e, 0x4f, 0x50, 0x45];
    const file = createMockFile(fakeMp4, "video/mp4", "fake.mp4");
    const result = await validateFileMagicNumber(file);
    assert.equal(result.valid, false);
  });

  await t.test("accepts valid JPEG and PNG images", async () => {
    const jpegBytes = [0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10];
    const jpeg = createMockFile(jpegBytes, "image/jpeg", "thumb.jpg");
    assert.equal((await validateFileMagicNumber(jpeg)).valid, true);

    const pngBytes = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    const png = createMockFile(pngBytes, "image/png", "thumb.png");
    assert.equal((await validateFileMagicNumber(png)).valid, true);
  });

  await t.test("accepts valid GIF images (GIF87a / GIF89a)", async () => {
    const gif87 = createMockFile([0x47, 0x49, 0x46, 0x38, 0x37, 0x61], "image/gif", "anim.gif");
    assert.equal((await validateFileMagicNumber(gif87)).valid, true);

    const gif89 = createMockFile([0x47, 0x49, 0x46, 0x38, 0x39, 0x61], "image/gif", "anim.gif");
    assert.equal((await validateFileMagicNumber(gif89)).valid, true);
  });

  await t.test("accepts valid WEBP images (RIFF....WEBP)", async () => {
    const webpBytes = [
      0x52, 0x49, 0x46, 0x46, // RIFF
      0x24, 0x00, 0x00, 0x00, // Size
      0x57, 0x45, 0x42, 0x50, // WEBP
    ];
    const webp = createMockFile(webpBytes, "image/webp", "image.webp");
    assert.equal((await validateFileMagicNumber(webp)).valid, true);
  });
});

test("Upload Validator — File size validation", async (t) => {
  await t.test("accepts file under 50MB limit", () => {
    const smallFile = createMockFile([1, 2, 3], "application/pdf", "doc.pdf", 10 * 1024 * 1024);
    const result = validateFileSize(smallFile, MAX_FILE_SIZE_BYTES);
    assert.equal(result.valid, true);
  });

  await t.test("rejects file exceeding 50MB limit", () => {
    const largeFile = createMockFile([1, 2, 3], "application/pdf", "doc.pdf", 55 * 1024 * 1024);
    const result = validateFileSize(largeFile, MAX_FILE_SIZE_BYTES);
    assert.equal(result.valid, false);
    assert.match(result.reason, /exceeds the maximum allowed limit/i);
  });

  await t.test("validates thumbnail max size (5MB)", () => {
    const validThumb = createMockFile([1], "image/png", "t.png", 4 * 1024 * 1024);
    assert.equal(validateFileSize(validThumb, MAX_THUMBNAIL_SIZE_BYTES).valid, true);

    const largeThumb = createMockFile([1], "image/png", "t.png", 6 * 1024 * 1024);
    assert.equal(validateFileSize(largeThumb, MAX_THUMBNAIL_SIZE_BYTES).valid, false);
  });
});

test("Upload Validator — MIME type allowlisting with validateUploadedFile", async (t) => {
  const allowed = ["application/pdf", "video/mp4", "image/png"];

  await t.test("rejects disallowed MIME type", async () => {
    const exeFile = createMockFile([0x4d, 0x5a], "application/x-msdownload", "malware.exe");
    const result = await validateUploadedFile(exeFile, allowed);
    assert.equal(result.valid, false);
    assert.match(result.reason, /unsupported file type/i);
  });

  await t.test("accepts allowed MIME type with valid signature", async () => {
    const pdfFile = createMockFile([0x25, 0x50, 0x44, 0x46], "application/pdf", "valid.pdf");
    const result = await validateUploadedFile(pdfFile, allowed);
    assert.equal(result.valid, true);
  });
});
