package fixture;

import android.widget.EditText;

class Settings {
    int level;

    void save(EditText field) {
        try {
            level = Integer.parseInt(field.getText().toString());
        } catch (NumberFormatException e) {
            field.setError("not a number");
        }
    }
}
