package org.example;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

// omweather's repaired Backup.zipExtract (run_20260929_231422): the canonical
// path and the separator-bounded startsWith are separate statements.
public class SplitCheck {
    public static void zipExtract(File targetDir, InputStream src) throws IOException {
        ZipEntry zipEntry;
        int readLen;
        byte[] readBuffer = new byte[4096];
        File extractionRoot = targetDir.getCanonicalFile();
        String extractionRootPath = extractionRoot.getPath();
        try (ZipInputStream zipInputStream = new ZipInputStream(src)) {
            while ((zipEntry = zipInputStream.getNextEntry()) != null) {
                File extractedFile = new File(extractionRoot, zipEntry.getName()).getCanonicalFile();
                String extractedFilePath = extractedFile.getPath();
                if (!extractedFilePath.equals(extractionRootPath)
                        && !extractedFilePath.startsWith(extractionRootPath + File.separator)) {
                    continue;
                }
                try (OutputStream outputStream = Files.newOutputStream(extractedFile.toPath())) {
                    while ((readLen = zipInputStream.read(readBuffer)) != -1) {
                        outputStream.write(readBuffer, 0, readLen);
                    }
                }
            }
        }
    }
}
