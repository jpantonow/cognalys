package org.example;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

// A canonical path and a startsWith that guard nothing: the entry name still
// escapes the destination, so the rule must keep firing.
public class UnrelatedStartsWith {
    public static void extract(File dest, InputStream src) throws IOException {
        String destPath = dest.getCanonicalPath();
        ZipInputStream zip = new ZipInputStream(src);
        ZipEntry entry;
        while ((entry = zip.getNextEntry()) != null) {
            if (entry.getName().startsWith(".")) {
                continue;
            }
            File out = new File(dest, entry.getName());
            FileOutputStream fos = new FileOutputStream(out);
            fos.close();
        }
        System.out.println(destPath);
    }
}
