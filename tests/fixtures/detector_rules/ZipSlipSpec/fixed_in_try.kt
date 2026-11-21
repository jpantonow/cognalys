package fixture

import java.io.File
import java.io.IOException
import java.util.zip.ZipInputStream

class Restorer(private val databasesDir: File) {
    fun restore(input: java.io.InputStream): Boolean {
        try {
            val zis = ZipInputStream(input)
            var zipEntry = zis.nextEntry
            while (zipEntry != null) {
                val file = File(databasesDir, zipEntry.name)
                if (!file.canonicalPath.startsWith(databasesDir.canonicalPath + File.separator)) {
                    throw IOException("entry outside destination")
                }
                file.outputStream().use { zis.copyTo(it) }
                zipEntry = zis.nextEntry
            }
            zis.close()
            return true
        } catch (e: IOException) {
            return false
        }
    }
}
