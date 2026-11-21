package fixture;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

class Extractor {
    static void extract(File archive, File destination) throws Exception {
        String root = destination.getCanonicalPath() + File.separator;
        ZipFile zipFile = new ZipFile(archive);
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            InputStream in = zipFile.getInputStream(entry);
            File target = new File(destination, entry.getName());
            if (!target.getCanonicalPath().startsWith(root)) {
                throw new SecurityException("entry outside destination");
            }
            FileOutputStream out = new FileOutputStream(target);
            in.transferTo(out);
            out.close();
        }
        zipFile.close();
    }
}
