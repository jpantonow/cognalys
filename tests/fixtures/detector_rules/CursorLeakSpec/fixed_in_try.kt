package fixture

import android.app.DownloadManager

class Status(private val downloadManager: DownloadManager) {
    fun check(id: Long): Int? {
        try {
            val cursor = downloadManager.query(DownloadManager.Query().setFilterById(id))
            try {
                if (cursor != null && cursor.moveToFirst()) {
                    return cursor.getInt(cursor.getColumnIndex(DownloadManager.COLUMN_STATUS))
                }
            } finally {
                cursor?.close()
            }
        } catch (e: IllegalStateException) {
            return null
        }
        return null
    }
}
