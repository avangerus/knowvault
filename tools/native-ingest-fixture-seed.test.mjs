import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { buildFixtureArtifacts } from "./native-ingest-fixture-seed.mjs";

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function inspectStoredZip(archive) {
  const localEntries = new Map();
  const localOffsets = new Map();
  let offset = 0;
  while (archive.readUInt32LE(offset) === 0x04034b50) {
    const method = archive.readUInt16LE(offset + 8);
    const checksum = archive.readUInt32LE(offset + 14);
    const size = archive.readUInt32LE(offset + 18);
    const nameLength = archive.readUInt16LE(offset + 26);
    const extraLength = archive.readUInt16LE(offset + 28);
    const nameStart = offset + 30;
    const name = archive.toString("ascii", nameStart, nameStart + nameLength);
    const dataStart = nameStart + nameLength + extraLength;
    const data = archive.subarray(dataStart, dataStart + size);
    assert.equal(method, 0, "fixture ZIP members use the stored method");
    assert.equal(data.length, size);
    assert.equal(crc32(data), checksum, "local member CRC matches its bytes");
    localEntries.set(name, data);
    localOffsets.set(name, offset);
    offset = dataStart + size;
  }

  assert.equal(archive.readUInt32LE(offset), 0x02014b50);
  const endOffset = archive.length - 22;
  assert.equal(archive.readUInt32LE(endOffset), 0x06054b50);
  const entryCount = archive.readUInt16LE(endOffset + 10);
  const centralSize = archive.readUInt32LE(endOffset + 12);
  const centralStart = archive.readUInt32LE(endOffset + 16);
  assert.equal(centralStart, offset);
  let centralOffset = centralStart;
  const centralNames = [];
  for (let index = 0; index < entryCount; index += 1) {
    assert.equal(archive.readUInt32LE(centralOffset), 0x02014b50);
    const method = archive.readUInt16LE(centralOffset + 10);
    const checksum = archive.readUInt32LE(centralOffset + 16);
    const nameLength = archive.readUInt16LE(centralOffset + 28);
    const extraLength = archive.readUInt16LE(centralOffset + 30);
    const commentLength = archive.readUInt16LE(centralOffset + 32);
    const localOffset = archive.readUInt32LE(centralOffset + 42);
    const nameStart = centralOffset + 46;
    const name = archive.toString("ascii", nameStart, nameStart + nameLength);
    const data = localEntries.get(name);
    assert.ok(data, "central member has a matching local member: " + name);
    assert.equal(method, 0);
    assert.equal(checksum, crc32(data));
    assert.equal(localOffsets.get(name), localOffset);
    centralNames.push(name);
    centralOffset += 46 + nameLength + extraLength + commentLength;
  }
  assert.equal(centralOffset, centralStart + centralSize);
  assert.deepEqual([...localEntries.keys()].sort(), centralNames.sort());
  return localEntries;
}

test("fixture originals and expected locators are deterministic and structurally complete", () => {
  const first = buildFixtureArtifacts();
  const second = buildFixtureArtifacts();
  const expectedNames = ["rule.docx", "report.pdf", "trips.xlsx"];
  assert.deepEqual([...first.artifacts.keys()], expectedNames);
  assert.deepEqual([...second.artifacts.keys()], expectedNames);

  for (const name of expectedNames) {
    const firstBytes = first.artifacts.get(name);
    const secondBytes = second.artifacts.get(name);
    assert.ok(firstBytes.equals(secondBytes), name + " bytes are reproducible");
  }
  assert.ok(first.manifestBytes.equals(second.manifestBytes));

  const manifest = JSON.parse(first.manifestBytes.toString("utf8"));
  assert.equal(manifest.ingestionRoot, "inbox");
  assert.deepEqual(
    manifest.artifacts.map((artifact) => artifact.path),
    expectedNames.map((name) => "inbox/" + name),
  );
  assert.equal(manifest.expectedFacts.approvedQuantityTotal, 40);
  assert.equal(manifest.expectedFacts.allRowQuantityTotal, 60);
  assert.deepEqual(manifest.expectedFacts.approvedQuantities, [10, 30]);
  for (const entry of manifest.artifacts) {
    const bytes = first.artifacts.get(entry.path.slice("inbox/".length));
    assert.equal(entry.bytes, bytes.length);
    assert.equal(entry.sha256, createHash("sha256").update(bytes).digest("hex"));
  }

  const docx = inspectStoredZip(first.artifacts.get("rule.docx"));
  assert.ok(docx.has("[Content_Types].xml"));
  assert.ok(docx.has("_rels/.rels"));
  assert.ok(docx.has("word/_rels/document.xml.rels"));
  assert.ok(docx.has("word/numbering.xml"));
  const docxContentTypes = docx.get("[Content_Types].xml").toString("utf8");
  const docxRootRels = docx.get("_rels/.rels").toString("utf8");
  const docxDocumentRels = docx.get("word/_rels/document.xml.rels").toString("utf8");
  assert.ok(docxContentTypes.includes('PartName="/word/document.xml"'));
  assert.ok(docxContentTypes.includes('PartName="/word/numbering.xml"'));
  assert.ok(docxRootRels.includes('Target="word/document.xml"'));
  assert.ok(docxDocumentRels.includes('Target="numbering.xml"'));
  const documentXml = docx.get("word/document.xml").toString("utf8");
  assert.ok(documentXml.includes("Northwind Fixture Company"));
  assert.match(documentXml, /<w:gridSpan w:val="4"\/>/);
  assert.match(documentXml, /<w:numId w:val="1"\/>/);

  const xlsx = inspectStoredZip(first.artifacts.get("trips.xlsx"));
  assert.ok(xlsx.has("[Content_Types].xml"));
  assert.ok(xlsx.has("_rels/.rels"));
  assert.ok(xlsx.has("xl/_rels/workbook.xml.rels"));
  assert.ok(xlsx.has("xl/styles.xml"));
  const xlsxContentTypes = xlsx.get("[Content_Types].xml").toString("utf8");
  const xlsxRootRels = xlsx.get("_rels/.rels").toString("utf8");
  const xlsxWorkbookRels = xlsx.get("xl/_rels/workbook.xml.rels").toString("utf8");
  assert.ok(xlsxContentTypes.includes('PartName="/xl/workbook.xml"'));
  assert.ok(xlsxContentTypes.includes('PartName="/xl/worksheets/sheet1.xml"'));
  assert.ok(xlsxRootRels.includes('Target="xl/workbook.xml"'));
  assert.ok(xlsxWorkbookRels.includes('Target="worksheets/sheet1.xml"'));
  assert.ok(xlsxWorkbookRels.includes('Target="styles.xml"'));
  const sheetXml = xlsx.get("xl/worksheets/sheet1.xml").toString("utf8");
  assert.match(sheetXml, /<mergeCell ref="A1:F1"\/>/);
  assert.match(sheetXml, /<c r="E3"><f>D3\*2<\/f><v>20<\/v><\/c>/);
  assert.match(sheetXml, /<c r="F6"><f>SUM\(D3:D5\)<\/f><v>60<\/v><\/c>/);
  assert.match(sheetXml, /<c r="C3" s="1"><v>46115<\/v><\/c>/);
  assert.match(sheetXml, /<c r="B4" t="inlineStr"><is><t xml:space="preserve">REJECTED<\/t><\/is><\/c>/);

  const pdf = first.artifacts.get("report.pdf").toString("ascii");
  assert.match(pdf, /^%PDF-1\.4/);
  assert.match(pdf, /\/Type \/Pages \/Kids \[3 0 R\] \/Count 1/);
  assert.ok(pdf.includes("SHIP-APR-02 is REJECTED"));
  assert.match(pdf, /Qualifying total: 40 units\./);
  assert.match(pdf, /Unfiltered sum of all quantities: 60 units\./);
});
