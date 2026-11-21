package fixture

import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipInputStream

class Importer(private val filesDir: File) {
    fun importNotes(input: java.io.InputStream) {
        ZipInputStream(input).use { zis ->
            var entry = zis.nextEntry
            while (entry != null) {
                val outputFile = File(filesDir, entry.name)
                FileOutputStream(outputFile).use { zis.copyTo(it) }
                entry = zis.nextEntry
            }
        }
    }
}
