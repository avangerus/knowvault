package local.knowvault.docparser;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellType;
import org.apache.poi.ss.usermodel.DataFormatter;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.util.CellReference;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

/**
 * XLSX structure observation. Emits one text unit per non-empty cell, identified by
 * sheet name and A1 cell reference.
 *
 * A formula is never evaluated (PARSER_CONTRACTS.md §3): the worker reports the
 * cached result the file already carries and raises a warning code, so a document
 * cannot make the parser compute anything. Hidden sheets, rows and cells are
 * extracted and flagged rather than silently dropped — the parser does not decide
 * visibility policy on its own.
 */
final class XlsxObserver {

    private XlsxObserver() {
    }

    static List<TextUnit> observe(byte[] document, Limits limits, List<String> warnings) {
        List<TextUnit> units = new ArrayList<>();
        long totalBytes = 0;
        boolean sawFormula = false;
        boolean sawHidden = false;
        boolean sawError = false;

        DataFormatter formatter = new DataFormatter(Locale.ROOT);
        try (XSSFWorkbook workbook = new XSSFWorkbook(new ByteArrayInputStream(document))) {
            for (int index = 0; index < workbook.getNumberOfSheets(); index++) {
                Sheet sheet = workbook.getSheetAt(index);
                if (workbook.isSheetHidden(index) || workbook.isSheetVeryHidden(index)) {
                    sawHidden = true;
                }
                String sheetName = sheet.getSheetName();
                if (sheetName == null || sheetName.isEmpty()) {
                    throw new WorkerException("AMBIGUOUS_SHEET_IDENTITY");
                }
                for (Row row : sheet) {
                    if (row.getZeroHeight()) {
                        sawHidden = true;
                    }
                    for (Cell cell : row) {
                        String rawText;
                        if (cell.getCellType() == CellType.FORMULA) {
                            sawFormula = true;
                            rawText = cachedFormulaValue(cell, formatter);
                            if (rawText == null) {
                                sawError = true;
                                continue;
                            }
                        } else {
                            rawText = formatter.formatCellValue(cell);
                        }
                        if (rawText == null || rawText.isEmpty()) {
                            continue;
                        }
                        String reference = new CellReference(cell.getRowIndex(), cell.getColumnIndex()).formatAsString();
                        Bounds.check(limits, units.size(), rawText, totalBytes);
                        totalBytes += rawText.getBytes(StandardCharsets.UTF_8).length;
                        units.add(TextUnit.xlsx(sheetName, reference, rawText));
                    }
                }
            }
        } catch (WorkerException e) {
            throw e;
        } catch (Exception e) {
            throw new WorkerException("PACKAGE_UNREADABLE");
        }

        if (units.isEmpty()) {
            throw new WorkerException("NO_EXTRACTABLE_TEXT");
        }
        if (sawFormula) {
            warnings.add("FORMULA_CACHED_VALUE_USED");
        }
        if (sawHidden) {
            warnings.add("HIDDEN_CONTENT_PRESENT");
        }
        if (sawError) {
            warnings.add("CELL_ERROR_VALUE_SKIPPED");
        }
        return units;
    }

    /** Reads the stored cached result. It never evaluates the formula. */
    private static String cachedFormulaValue(Cell cell, DataFormatter formatter) {
        return switch (cell.getCachedFormulaResultType()) {
            case STRING -> cell.getRichStringCellValue().getString();
            case BOOLEAN -> cell.getBooleanCellValue() ? "TRUE" : "FALSE";
            case NUMERIC -> formatter.formatRawCellContents(
                    cell.getNumericCellValue(),
                    cell.getCellStyle().getDataFormat(),
                    cell.getCellStyle().getDataFormatString());
            default -> null;
        };
    }
}
