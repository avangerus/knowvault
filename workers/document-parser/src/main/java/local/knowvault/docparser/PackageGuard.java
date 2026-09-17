package local.knowvault.docparser;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;

/**
 * Raw-package safety gate (PARSER_CONTRACTS.md §3, ADR-0062 §4).
 *
 * It runs over the raw ZIP bytes BEFORE any OOXML library opens them, so the
 * decision does not depend on the library's own defaults or on a version upgrade
 * keeping them. Every class below is a refusal, never a partial extraction and never
 * a "best effort": an OOXML package that carries a macro, an embedded object, an
 * external relationship, a traversal or duplicate entry, a DTD/entity, or that
 * exceeds an entry/total/ratio bound is rejected outright.
 */
final class PackageGuard {

    private static final String[] FORBIDDEN_PATH_FRAGMENTS = {
            "vbaproject.bin",
            "/embeddings/",
            "oleobject",
            "/activex/",
            "vbadata.xml",
    };

    private PackageGuard() {
    }

    static void verify(byte[] document, Limits limits) {
        if (document.length == 0 || document.length > limits.maxInputBytes()) {
            throw new WorkerException("INPUT_SIZE_REJECTED");
        }
        if (!(document.length > 4 && document[0] == 'P' && document[1] == 'K')) {
            throw new WorkerException("MEDIA_SIGNATURE_MISMATCH");
        }

        verifyCentralDirectory(document, limits);

        Set<String> seen = new HashSet<>();
        long totalUncompressed = 0;
        int entries = 0;
        byte[] buffer = new byte[64 * 1024];

        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(document), StandardCharsets.UTF_8)) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                entries++;
                if (entries > limits.maxZipEntries()) {
                    throw new WorkerException("ZIP_ENTRY_COUNT_EXCEEDED");
                }
                String name = entry.getName();
                verifyEntryName(name);
                String normalized = name.toLowerCase(Locale.ROOT);
                if (!seen.add(normalized)) {
                    throw new WorkerException("ZIP_DUPLICATE_ENTRY");
                }
                verifyForbiddenPath(normalized);

                long uncompressed = 0;
                int read;
                StringBuilder head = new StringBuilder();
                boolean inspectable = normalized.endsWith(".xml") || normalized.endsWith(".rels");
                while ((read = zip.read(buffer)) > 0) {
                    uncompressed += read;
                    if (uncompressed > limits.maxEntryBytes()) {
                        throw new WorkerException("ZIP_ENTRY_SIZE_EXCEEDED");
                    }
                    totalUncompressed += read;
                    if (totalUncompressed > limits.maxTotalUncompressedBytes()) {
                        throw new WorkerException("ZIP_TOTAL_SIZE_EXCEEDED");
                    }
                    if (inspectable && head.length() < 262144) {
                        head.append(new String(buffer, 0, read, StandardCharsets.UTF_8));
                    }
                }
                if (inspectable) {
                    verifyXmlPart(head.toString());
                }
                long compressed = entry.getCompressedSize();
                if (compressed > 0 && uncompressed > 0) {
                    double ratio = (double) compressed / (double) uncompressed;
                    if (ratio < limits.minInflateRatio()) {
                        throw new WorkerException("ZIP_INFLATE_RATIO_REJECTED");
                    }
                }
                zip.closeEntry();
            }
        } catch (WorkerException e) {
            throw e;
        } catch (IOException e) {
            throw new WorkerException("PACKAGE_UNREADABLE");
        }

        if (entries == 0) {
            throw new WorkerException("PACKAGE_UNREADABLE");
        }
        if (!seen.contains("[content_types].xml")) {
            throw new WorkerException("MEDIA_SIGNATURE_MISMATCH");
        }
    }

    /**
     * Checks the ZIP central directory before opening a decompressor.  A
     * {@link ZipInputStream} only learns the final sizes for entries delivered
     * with a data descriptor after it has inflated the entry; that makes a
     * highly-compressible entry able to consume the worker's wall-clock budget
     * before the existing size/ratio checks can refuse it.  Commons Compress
     * reads the seekable central directory in-place, so the declared bounds are
     * enforced while the package is still only metadata.
     */
    private static void verifyCentralDirectory(byte[] document, Limits limits) {
        Set<String> seen = new HashSet<>();
        long totalUncompressed = 0;
        int entries = 0;
        try (SeekableByteChannel channel = new SeekableInMemoryByteChannel(document);
             ZipFile zip = new ZipFile(channel)) {
            for (java.util.Enumeration<ZipArchiveEntry> iterator = zip.getEntries(); iterator.hasMoreElements();) {
                ZipArchiveEntry entry = iterator.nextElement();
                entries++;
                if (entries > limits.maxZipEntries()) {
                    throw new WorkerException("ZIP_ENTRY_COUNT_EXCEEDED");
                }

                String name = entry.getName();
                verifyEntryName(name);
                String normalized = name.toLowerCase(Locale.ROOT);
                if (!seen.add(normalized)) {
                    throw new WorkerException("ZIP_DUPLICATE_ENTRY");
                }
                verifyForbiddenPath(normalized);

                long uncompressed = entry.getSize();
                long compressed = entry.getCompressedSize();
                // A central directory with unknown sizes cannot be bounded before
                // inflation. Fail closed instead of falling back to a streaming
                // guess, which would reintroduce the descriptor/bomb race.
                if (uncompressed < 0 || compressed < 0) {
                    throw new WorkerException("PACKAGE_UNREADABLE");
                }
                if (uncompressed > limits.maxEntryBytes()) {
                    throw new WorkerException("ZIP_ENTRY_SIZE_EXCEEDED");
                }
                if (Long.MAX_VALUE - totalUncompressed < uncompressed) {
                    throw new WorkerException("ZIP_TOTAL_SIZE_EXCEEDED");
                }
                totalUncompressed += uncompressed;
                if (totalUncompressed > limits.maxTotalUncompressedBytes()) {
                    throw new WorkerException("ZIP_TOTAL_SIZE_EXCEEDED");
                }
                if (uncompressed > 0) {
                    if (compressed <= 0
                            || ((double) compressed / (double) uncompressed) < limits.minInflateRatio()) {
                        throw new WorkerException("ZIP_INFLATE_RATIO_REJECTED");
                    }
                }
            }
        } catch (WorkerException e) {
            throw e;
        } catch (IOException | RuntimeException e) {
            throw new WorkerException("PACKAGE_UNREADABLE");
        }
        if (entries == 0 || !seen.contains("[content_types].xml")) {
            throw new WorkerException("MEDIA_SIGNATURE_MISMATCH");
        }
    }

    private static void verifyForbiddenPath(String normalized) {
        for (String forbidden : FORBIDDEN_PATH_FRAGMENTS) {
            if (normalized.contains(forbidden)) {
                throw new WorkerException("ACTIVE_CONTENT_REJECTED");
            }
        }
    }

    private static void verifyEntryName(String name) {
        if (name.isEmpty() || name.length() > 1024) {
            throw new WorkerException("ZIP_ENTRY_NAME_REJECTED");
        }
        if (name.startsWith("/") || name.contains("\\") || name.contains("..") || name.contains(":")) {
            throw new WorkerException("ZIP_ENTRY_NAME_REJECTED");
        }
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                throw new WorkerException("ZIP_ENTRY_NAME_REJECTED");
            }
        }
    }

    private static void verifyXmlPart(String text) {
        String lowered = text.toLowerCase(Locale.ROOT);
        if (lowered.contains("<!doctype") || lowered.contains("<!entity") || lowered.contains("<?xml-stylesheet")
                || lowered.contains("xi:include")) {
            throw new WorkerException("XML_EXTERNAL_CONSTRUCT_REJECTED");
        }
        if (lowered.contains("targetmode=\"external\"") || lowered.contains("targetmode='external'")) {
            throw new WorkerException("EXTERNAL_RELATIONSHIP_REJECTED");
        }
        if (lowered.contains("ms-word.stylewithdata") || lowered.contains("vbaproject")) {
            throw new WorkerException("ACTIVE_CONTENT_REJECTED");
        }
        if (lowered.contains("application/vnd.ms-office.vbaproject")
                || lowered.contains("macroenabled")) {
            throw new WorkerException("ACTIVE_CONTENT_REJECTED");
        }
    }
}
