package fixture

import android.app.DownloadManager

class Status(private val downloadManager: DownloadManager) {
    fun check(id: Long): Int? {
        val cursor = downloadManager.query(DownloadManager.Query().setFilterById(id))
        if (cursor != null && cursor.moveToFirst()) {
            val status = cursor.getInt(cursor.getColumnIndex(DownloadManager.COLUMN_STATUS))
            cursor.close()
            return status
        }
        return null
    }
}
