package fixture

import android.app.DownloadManager

class Status(private val downloadManager: DownloadManager) {
    fun check(id: Long): Int? {
        val cursor = downloadManager.query(DownloadManager.Query().setFilterById(id))
        cursor?.use {
            if (it.moveToFirst()) {
                return it.getInt(it.getColumnIndex(DownloadManager.COLUMN_STATUS))
            }
        }
        return null
    }
}
