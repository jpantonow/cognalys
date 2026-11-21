package fixture;

import android.widget.EditText;

class Settings {
    int level;

    void save(EditText field) {
        level = Integer.parseInt(field.getText().toString());
    }
}
