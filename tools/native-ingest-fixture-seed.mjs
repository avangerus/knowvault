#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  closeSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const COMPANY = "Northwind Fixture Company";
const PERIOD = "April 2026";
const RULE =
  "Rule: Count only shipments with Status = APPROVED; use the whole-number Quantity as recorded and sum qualifying rows for the monthly total.";
const LIST_ITEMS = [
  "Filter the shipment register to Status = APPROVED.",
  "Use each qualifying whole-number Quantity without rounding.",
];
const RECORDS = [
  { id: "SHIP-APR-01", status: "APPROVED", date: "2026-04-03", quantity: 10 },
  { id: "SHIP-APR-02", status: "REJECTED", date: "2026-04-15", quantity: 20 },
  { id: "SHIP-APR-03", status: "APPROVED", date: "2026-04-28", quantity: 30 },
];

const DOCX_TYPE =
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
const XLSX_TYPE =
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
const PDF_TYPE = "application/pdf";

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function escapeXml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function xmlText(value) {
  return "<w:r><w:t xml:space=\"preserve\">" + escapeXml(value) + "</w:t></w:r>";
}

function docxParagraph(value, numId) {
  const numbering = numId
    ? "<w:pPr><w:numPr><w:ilvl w:val=\"0\"/><w:numId w:val=\"" +
      numId +
      "\"/></w:numPr></w:pPr>"
    : "";
  return "<w:p>" + numbering + xmlText(value) + "</w:p>";
}

function docxCell(value, gridSpan) {
  const span = gridSpan
    ? "<w:tcPr><w:gridSpan w:val=\"" + gridSpan + "\"/></w:tcPr>"
    : "";
  return "<w:tc>" + span + docxParagraph(value) + "</w:tc>";
}

function docxRow(cells, isHeader) {
  const header = isHeader
    ? "<w:trPr><w:tblHeader w:val=\"true\"/></w:trPr>"
    : "";
  return "<w:tr>" + header + cells.join("") + "</w:tr>";
}

function buildDocx() {
  const borders =
    "<w:tblBorders>" +
    "<w:top w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"808080\"/>" +
    "<w:left w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"808080\"/>" +
    "<w:bottom w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"808080\"/>" +
    "<w:right w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"808080\"/>" +
    "<w:insideH w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"808080\"/>" +
    "<w:insideV w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"808080\"/>" +
    "</w:tblBorders>";
  const columns =
    "<w:tblGrid>" +
    "<w:gridCol w:w=\"1800\"/><w:gridCol w:w=\"1700\"/>" +
    "<w:gridCol w:w=\"2200\"/><w:gridCol w:w=\"1500\"/>" +
    "</w:tblGrid>";
  const headerRows = [
    docxRow([docxCell(COMPANY + " | " + PERIOD + " shipment register", 4)], true),
    docxRow(["Record ID", "Status", "Activity Date", "Quantity"].map((value) => docxCell(value)), true),
  ];
  const dataRows = RECORDS.map((record) =>
    docxRow(
      [record.id, record.status, record.date, String(record.quantity)].map((value) =>
        docxCell(value),
      ),
      false,
    ),
  );
  const table =
    "<w:tbl><w:tblPr><w:tblW w:w=\"0\" w:type=\"auto\"/>" +
    borders +
    "</w:tblPr>" +
    columns +
    headerRows.join("") +
    dataRows.join("") +
    "</w:tbl>";
  const documentXml =
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
    "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">" +
    "<w:body>" +
    docxParagraph(COMPANY + " | " + PERIOD) +
    docxParagraph(RULE) +
    docxParagraph(LIST_ITEMS[0], 1) +
    docxParagraph(LIST_ITEMS[1], 1) +
    docxParagraph("The three approved shipment records appear in the table below.") +
    table +
    "<w:sectPr><w:pgSz w:w=\"12240\" w:h=\"15840\"/>" +
    "<w:pgMar w:top=\"1440\" w:right=\"1440\" w:bottom=\"1440\" w:left=\"1440\" " +
    "w:header=\"720\" w:footer=\"720\" w:gutter=\"0\"/></w:sectPr>" +
    "</w:body></w:document>";
  const numberingXml =
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
    "<w:numbering xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">" +
    "<w:abstractNum w:abstractNumId=\"0\"><w:multiLevelType w:val=\"singleLevel\"/>" +
    "<w:lvl w:ilvl=\"0\"><w:start w:val=\"1\"/><w:numFmt w:val=\"bullet\"/>" +
    "<w:lvlText w:val=\"&#x2022;\"/><w:lvlJc w:val=\"left\"/>" +
    "<w:pPr><w:ind w:left=\"720\" w:hanging=\"360\"/></w:pPr>" +
    "</w:lvl></w:abstractNum><w:num w:numId=\"1\">" +
    "<w:abstractNumId w:val=\"0\"/></w:num></w:numbering>";
  const contentTypes =
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
    "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">" +
    "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>" +
    "<Default Extension=\"xml\" ContentType=\"application/xml\"/>" +
    "<Override PartName=\"/word/document.xml\" " +
    "ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>" +
    "<Override PartName=\"/word/numbering.xml\" " +
    "ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml\"/>" +
    "</Types>";
  const rootRels =
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
    "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">" +
    "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" " +
    "Target=\"word/document.xml\"/></Relationships>";
  const documentRels =
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
    "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">" +
    "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering\" " +
    "Target=\"numbering.xml\"/></Relationships>";
  return zipStore([
    ["[Content_Types].xml", contentTypes],
    ["_rels/.rels", rootRels],
    ["word/_rels/document.xml.rels", documentRels],
    ["word/document.xml", documentXml],
    ["word/numbering.xml", numberingXml],
  ]);
}

function inlineStringCell(reference, value, styleIndex) {
  const style = styleIndex === undefined ? "" : " s=\"" + styleIndex + "\"";
  return (
    "<c r=\"" +
    reference +
    "\" t=\"inlineStr\"" +
    style +
    "><is><t xml:space=\"preserve\">" +
    escapeXml(value) +
    "</t></is></c>"
  );
}

function numericCell(reference, value, styleIndex) {
  const style = styleIndex === undefined ? "" : " s=\"" + styleIndex + "\"";
  return "<c r=\"" + reference + "\"" + style + "><v>" + value + "</v></c>";
}

function formulaCell(reference, formula, cachedValue) {
  return (
    "<c r=\"" +
    reference +
    "\"><f>" +
    formula +
    "</f><v>" +
    cachedValue +
    "</v></c>"
  );
}

function excelDateSerial(isoDate) {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(isoDate);
  if (!match) throw new Error("Invalid fixture date: " + isoDate);
  const utc = Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
  return Math.round((utc - Date.UTC(1899, 11, 30)) / 86400000);
}

function buildXlsx() {
  const header =
    "<row r=\"1\">" +
    inlineStringCell("A1", COMPANY + " | " + PERIOD + " shipment register") +
    "</row><row r=\"2\">" +
    [
      "Record ID",
      "Status",
      "Activity Date",
      "Quantity",
      "Double Quantity",
      "All-Row Sum (Reference)",
    ]
      .map((value, index) => inlineStringCell(String.fromCharCode(65 + index) + "2", value))
      .join("") +
    "</row>";
  const rows = RECORDS.map((record, index) => {
    const row = index + 3;
    return (
      "<row r=\"" +
      row +
      "\">" +
      inlineStringCell("A" + row, record.id) +
      inlineStringCell("B" + row, record.status) +
      numericCell("C" + row, excelDateSerial(record.date), 1) +
      numericCell("D" + row, record.quantity) +
      formulaCell("E" + row, "D" + row + "*2", record.quantity * 2) +
      "</row>"
    );
  }).join("");
  const sheetXml =
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
    "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" " +
    "xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">" +
    "<dimension ref=\"A1:F6\"/><sheetViews><sheetView workbookViewId=\"0\"/></sheetViews>" +
    "<sheetFormatPr defaultRowHeight=\"15\"/>" +
    "<cols><col min=\"1\" max=\"1\" width=\"18\" customWidth=\"1\"/>" +
    "<col min=\"2\" max=\"2\" width=\"14\" customWidth=\"1\"/>" +
    "<col min=\"3\" max=\"3\" width=\"16\" customWidth=\"1\"/>" +
    "<col min=\"4\" max=\"5\" width=\"18\" customWidth=\"1\"/>" +
    "<col min=\"6\" max=\"6\" width=\"26\" customWidth=\"1\"/></cols>" +
    "<sheetData>" +
    header +
    rows +
    "<row r=\"6\">" +
    inlineStringCell("D6", "SUM of all rows (unfiltered)") +
    formulaCell("F6", "SUM(D3:D5)", 60) +
    "</row></sheetData><mergeCells count=\"1\"><mergeCell ref=\"A1:F1\"/></mergeCells>" +
    "<pageMargins left=\"0.7\" right=\"0.7\" top=\"0.75\" bottom=\"0.75\" header=\"0.3\" footer=\"0.3\"/>" +
    "</worksheet>";
  const workbookXml =
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
    "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" " +
    "xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">" +
    "<bookViews><workbookView xWindow=\"0\" yWindow=\"0\" windowWidth=\"24000\" " +
    "windowHeight=\"12000\" activeTab=\"0\"/></bookViews>" +
    "<sheets><sheet name=\"Monthly Ledger\" sheetId=\"1\" r:id=\"rId1\"/></sheets>" +
    "<calcPr calcId=\"191029\" calcMode=\"auto\" fullCalcOnLoad=\"1\" forceFullCalc=\"1\"/>" +
    "</workbook>";
  const stylesXml =
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
    "<styleSheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">" +
    "<numFmts count=\"1\"><numFmt numFmtId=\"164\" formatCode=\"yyyy-mm-dd\"/></numFmts>" +
    "<fonts count=\"1\"><font><sz val=\"11\"/><color theme=\"1\"/><name val=\"Calibri\"/>" +
    "<family val=\"2\"/></font></fonts>" +
    "<fills count=\"2\"><fill><patternFill patternType=\"none\"/></fill>" +
    "<fill><patternFill patternType=\"gray125\"/></fill></fills>" +
    "<borders count=\"1\"><border><left/><right/><top/><bottom/><diagonal/></border></borders>" +
    "<cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs>" +
    "<cellXfs count=\"2\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\"/>" +
    "<xf numFmtId=\"164\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\" applyNumberFormat=\"1\"/>" +
    "</cellXfs><cellStyles count=\"1\"><cellStyle name=\"Normal\" xfId=\"0\" builtinId=\"0\"/></cellStyles>" +
    "<tableStyles count=\"0\" defaultTableStyle=\"TableStyleMedium2\" defaultPivotStyle=\"PivotStyleLight16\"/>" +
    "</styleSheet>";
  const contentTypes =
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
    "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">" +
    "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>" +
    "<Default Extension=\"xml\" ContentType=\"application/xml\"/>" +
    "<Override PartName=\"/xl/workbook.xml\" " +
    "ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>" +
    "<Override PartName=\"/xl/worksheets/sheet1.xml\" " +
    "ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>" +
    "<Override PartName=\"/xl/styles.xml\" " +
    "ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/>" +
    "</Types>";
  const rootRels =
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
    "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">" +
    "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" " +
    "Target=\"xl/workbook.xml\"/></Relationships>";
  const workbookRels =
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
    "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">" +
    "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" " +
    "Target=\"worksheets/sheet1.xml\"/>" +
    "<Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" " +
    "Target=\"styles.xml\"/></Relationships>";
  return zipStore([
    ["[Content_Types].xml", contentTypes],
    ["_rels/.rels", rootRels],
    ["xl/_rels/workbook.xml.rels", workbookRels],
    ["xl/styles.xml", stylesXml],
    ["xl/workbook.xml", workbookXml],
    ["xl/worksheets/sheet1.xml", sheetXml],
  ]);
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function zipStore(entries) {
  const sorted = entries
    .map(([name, contents]) => [name, Buffer.isBuffer(contents) ? contents : Buffer.from(contents, "utf8")])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const localParts = [];
  const centralParts = [];
  let localOffset = 0;
  const dosDate = 33;

  for (const [name, contents] of sorted) {
    const filename = Buffer.from(name, "ascii");
    const checksum = crc32(contents);
    if (contents.length > 0xffffffff || localOffset > 0xffffffff) {
      throw new Error("Fixture ZIP exceeds classic ZIP limits");
    }
    const local = Buffer.alloc(30 + filename.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(dosDate, 12);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(contents.length, 18);
    local.writeUInt32LE(contents.length, 22);
    local.writeUInt16LE(filename.length, 26);
    local.writeUInt16LE(0, 28);
    filename.copy(local, 30);
    localParts.push(local, contents);

    const central = Buffer.alloc(46 + filename.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt16LE(0, 12);
    central.writeUInt16LE(dosDate, 14);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(contents.length, 20);
    central.writeUInt32LE(contents.length, 24);
    central.writeUInt16LE(filename.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(localOffset, 42);
    filename.copy(central, 46);
    centralParts.push(central);
    localOffset += local.length + contents.length;
  }

  const centralDirectory = Buffer.concat(centralParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(sorted.length, 8);
  end.writeUInt16LE(sorted.length, 10);
  end.writeUInt32LE(centralDirectory.length, 12);
  end.writeUInt32LE(localOffset, 16);
  end.writeUInt16LE(0, 20);
  return Buffer.concat([...localParts, centralDirectory, end]);
}

function pdfString(value) {
  return String(value).replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}

function buildPdf() {
  const content = Buffer.from(
    [
      "BT",
      "/F1 18 Tf",
      "54 740 Td",
      "(" + pdfString(COMPANY) + ") Tj",
      "0 -28 Td",
      "/F1 14 Tf",
      "(" + pdfString(PERIOD + " close note") + ") Tj",
      "/F1 11 Tf",
      "0 -36 Td",
      "(Only APPROVED shipments count toward the monthly total.) Tj",
      "0 -20 Td",
      "(SHIP-APR-01 and SHIP-APR-03 are APPROVED; SHIP-APR-02 is REJECTED.) Tj",
      "0 -20 Td",
      "(Approved quantities: 10 and 30 units. Qualifying total: 40 units.) Tj",
      "0 -20 Td",
      "(Unfiltered sum of all quantities: 60 units.) Tj",
      "ET",
    ].join("\n"),
    "ascii",
  );
  const header = Buffer.from("%PDF-1.4\n%Synthetic fixture\n", "ascii");
  const bodies = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] " +
      "/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    "<< /Length " + content.length + " >>\nstream\n" + content.toString("ascii") + "\nendstream",
  ];
  const chunks = [header];
  const offsets = [0];
  let offset = header.length;
  for (let i = 0; i < bodies.length; i += 1) {
    offsets.push(offset);
    const object = Buffer.from(i + 1 + " 0 obj\n" + bodies[i] + "\nendobj\n", "ascii");
    chunks.push(object);
    offset += object.length;
  }
  const xrefOffset = offset;
  const xref =
    "xref\n0 6\n0000000000 65535 f \n" +
    offsets.slice(1).map((value) => String(value).padStart(10, "0") + " 00000 n \n").join("") +
    "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n" +
    xrefOffset +
    "\n%%EOF\n";
  chunks.push(Buffer.from(xref, "ascii"));
  return Buffer.concat(chunks);
}

function expectedEntry(filename, mediaType, bytes, expected) {
  return {
    path: "inbox/" + filename,
    mediaType,
    bytes: bytes.length,
    sha256: sha256(bytes),
    expected,
  };
}

function expectedText(text, locator, extra) {
  return { text, locator, ...(extra || {}) };
}

export function buildFixtureArtifacts() {
  const rule = buildDocx();
  const report = buildPdf();
  const workbook = buildXlsx();
  const artifacts = new Map([
    ["rule.docx", rule],
    ["report.pdf", report],
    ["trips.xlsx", workbook],
  ]);
  const manifest = {
    schemaVersion: 1,
    fixture: "synthetic-month-company",
    ingestionRoot: "inbox",
    company: COMPANY,
    period: PERIOD,
    expectedFacts: {
      qualifyingStatus: "APPROVED",
      approvedRecordCount: 2,
      quantities: [10, 20, 30],
      approvedQuantities: [10, 30],
      approvedQuantityTotal: 40,
      allRowQuantityTotal: 60,
    },
    artifacts: [
      expectedEntry("rule.docx", DOCX_TYPE, rule, [
        expectedText(COMPANY + " | " + PERIOD, {
          kind: "docx.paragraph",
          paragraph: 1,
        }),
        expectedText(RULE, {
          kind: "docx.paragraph",
          paragraph: 2,
        }),
        expectedText(LIST_ITEMS[0], {
          kind: "docx.paragraph",
          paragraph: 3,
        }),
        expectedText(LIST_ITEMS[1], {
          kind: "docx.paragraph",
          paragraph: 4,
        }),
        expectedText(COMPANY + " | " + PERIOD + " shipment register", {
          kind: "docx.table.cell",
          table: 1,
          row: 1,
          cell: 1,
          mergedRange: "1-4",
        }),
        expectedText("10", {
          kind: "docx.table.cell",
          table: 1,
          row: 3,
          cell: 4,
        }),
        expectedText("REJECTED", {
          kind: "docx.table.cell",
          table: 1,
          row: 4,
          cell: 2,
        }),
        expectedText("20", {
          kind: "docx.table.cell",
          table: 1,
          row: 4,
          cell: 4,
        }),
        expectedText("30", {
          kind: "docx.table.cell",
          table: 1,
          row: 5,
          cell: 4,
        }),
      ]),
      expectedEntry("report.pdf", PDF_TYPE, report, [
        expectedText(COMPANY, { kind: "pdf.page", page: 1 }),
        expectedText(PERIOD + " close note", { kind: "pdf.page", page: 1 }),
        expectedText("Qualifying total: 40 units.", { kind: "pdf.page", page: 1 }),
        expectedText("Unfiltered sum of all quantities: 60 units.", {
          kind: "pdf.page",
          page: 1,
        }),
      ]),
      expectedEntry("trips.xlsx", XLSX_TYPE, workbook, [
        expectedText(COMPANY + " | " + PERIOD + " shipment register", {
          kind: "xlsx.cell",
          sheet: "Monthly Ledger",
          cell: "A1",
          mergedRange: "A1:F1",
        }),
        expectedText("SHIP-APR-01", {
          kind: "xlsx.cell",
          sheet: "Monthly Ledger",
          cell: "A3",
        }),
        expectedText("2026-04-03", {
          kind: "xlsx.cell",
          sheet: "Monthly Ledger",
          cell: "C3",
          storage: "excel-date",
        }),
        expectedText("10", {
          kind: "xlsx.cell",
          sheet: "Monthly Ledger",
          cell: "D3",
        }),
        expectedText("20", {
          kind: "xlsx.cell",
          sheet: "Monthly Ledger",
          cell: "E3",
          formula: "=D3*2",
          cachedResult: "20",
        }),
        expectedText("REJECTED", {
          kind: "xlsx.cell",
          sheet: "Monthly Ledger",
          cell: "B4",
        }),
        expectedText("20", {
          kind: "xlsx.cell",
          sheet: "Monthly Ledger",
          cell: "D4",
        }),
        expectedText("30", {
          kind: "xlsx.cell",
          sheet: "Monthly Ledger",
          cell: "D5",
        }),
        expectedText("60", {
          kind: "xlsx.cell",
          sheet: "Monthly Ledger",
          cell: "F6",
          formula: "=SUM(D3:D5)",
          cachedResult: "60",
          meaning: "unfiltered reference sum",
        }),
      ]),
    ],
  };
  const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2) + "\n", "utf8");
  return { artifacts, manifest, manifestBytes };
}

function parseArgs(args) {
  let outputRoot;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--out") {
      if (outputRoot !== undefined || args[index + 1] === undefined) {
        throw new Error("Use --out <isolated-directory> exactly once");
      }
      outputRoot = args[index + 1];
      index += 1;
    } else if (arg.startsWith("--out=")) {
      if (outputRoot !== undefined || arg.slice("--out=".length) === "") {
        throw new Error("Use --out <isolated-directory> exactly once");
      }
      outputRoot = arg.slice("--out=".length);
    } else {
      throw new Error("Unknown argument: " + arg);
    }
  }
  if (!outputRoot) throw new Error("An explicit --out <isolated-directory> is required");
  return path.resolve(outputRoot);
}

function assertSafeOutputRoot(outputRoot) {
  const filesystemRoot = path.parse(outputRoot).root;
  const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  if (outputRoot === filesystemRoot || outputRoot === workspaceRoot) {
    throw new Error("Refusing a filesystem or workspace root; choose an isolated --out directory");
  }
  let parent;
  try {
    parent = lstatSync(path.dirname(outputRoot));
  } catch {
    throw new Error("The parent of --out must already exist: " + path.dirname(outputRoot));
  }
  if (!parent.isDirectory()) {
    throw new Error("The parent of --out must be a directory: " + path.dirname(outputRoot));
  }
  try {
    const info = lstatSync(outputRoot);
    if (info.isSymbolicLink() || !info.isDirectory()) {
      throw new Error("The --out path must be a plain directory, not a link or file");
    }
    if (readdirSync(outputRoot).length !== 0) {
      throw new Error("Refusing to write into a non-empty --out directory");
    }
    return true;
  } catch (error) {
    if (error && error.code === "ENOENT") return false;
    throw error;
  }
}

function writeNewFile(filename, bytes) {
  const descriptor = openSync(filename, "wx");
  try {
    writeFileSync(descriptor, bytes);
  } finally {
    closeSync(descriptor);
  }
}

export function prepareFixtureOutput(outputRoot) {
  const absoluteRoot = path.resolve(outputRoot);
  const outputRootExists = assertSafeOutputRoot(absoluteRoot);
  const { artifacts, manifestBytes } = buildFixtureArtifacts();
  const manifestPath = path.join(absoluteRoot, "expected.json");
  const inboxPath = path.join(absoluteRoot, "inbox");

  if (!outputRootExists) mkdirSync(absoluteRoot);
  mkdirSync(inboxPath);
  for (const [filename, bytes] of artifacts) {
    writeNewFile(path.join(inboxPath, filename), bytes);
  }
  writeNewFile(manifestPath, manifestBytes);

  const writtenFiles = [];
  for (const [filename, bytes] of artifacts) {
    writtenFiles.push({
      path: "inbox/" + filename,
      bytes: bytes.length,
      sha256: sha256(bytes),
    });
  }
  return {
    status: "prepared",
    outputRoot: absoluteRoot,
    ingestionRoot: inboxPath,
    manifest: "expected.json",
    manifestBytes: manifestBytes.length,
    manifestSha256: sha256(manifestBytes),
    files: writtenFiles,
  };
}

function isMainModule() {
  return (
    process.argv[1] !== undefined &&
    path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
  );
}

if (isMainModule()) {
  try {
    const outputRoot = parseArgs(process.argv.slice(2));
    const receipt = prepareFixtureOutput(outputRoot);
    process.stdout.write(JSON.stringify(receipt, null, 2) + "\n");
  } catch (error) {
    process.stderr.write("native-ingest-fixture-seed: " + error.message + "\n");
    process.exitCode = 1;
  }
}
