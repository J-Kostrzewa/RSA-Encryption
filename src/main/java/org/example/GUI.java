package org.example;
import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import java.io.File;
import java.io.IOException;
import java.net.URL;

public class GUI extends Application {
    private TextArea inputTextArea;
    private TextArea outputTextArea;
    private TextArea nKeyArea;     // Osobne pole na wyświetlenie modułu n
    private TextArea eKeyArea;     // Osobne pole na wyświetlenie wykładnika publicznego e
    private TextArea dKeyArea;     // Osobne pole na wyświetlenie wykładnika prywatnego d
    private ComboBox<String> keySizeComboBox;
    private RadioButton fileRadio;
    private RadioButton textRadio;
    private Label selectedFileLabel;
    private File selectedFile;
    private RSA rsa;
    private RadioButton publicKeyRadio;
    private RadioButton privateKeyRadio;

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("RSA Encryption/Decryption");

        // Utworzenie głównego układu
        VBox root = new VBox(10);
        root.setPadding(new Insets(10));
        root.setStyle("-fx-background-color: #2b2b2b;");

        // Ciemny motyw dla sceny
        Scene scene = new Scene(root, 800, 700);

        // Panel górny
        HBox topPanel = createTopPanel();

        // Panel środkowy
        VBox centerPanel = createCenterPanel();

        // Panel dolny
        VBox bottomPanel = createBottomPanel();

        // Dodanie paneli do głównej sceny
        root.getChildren().addAll(topPanel, centerPanel, bottomPanel);
        primaryStage.setScene(scene);

        primaryStage.getScene().getRoot().setStyle("-fx-border-color: black; -fx-border-width: 2;");
        primaryStage.show();

        // Utworzenie początkowej instancji RSA z domyślnymi parametrami
        rsa = new RSA(2048);
        updateKeyDisplay();
    }

    // Zastosowanie stylów inline, gdy plik CSS nie jest dostępny
    private void applyInlineStyles(VBox root) {
        root.setStyle("-fx-background-color: #2b2b2b;");
    }

    // Utworzenie panelu górnego
    private HBox createTopPanel() {
        HBox topPanel = new HBox(10);
        topPanel.setAlignment(Pos.CENTER_LEFT);

        // Wybór długości klucza
        Label keySizeLabel = new Label("Długość klucza:");
        keySizeComboBox = new ComboBox<>();
        keySizeComboBox.getItems().addAll("1024 bits", "2048 bits", "4096 bits");
        keySizeComboBox.setValue("2048 bits");

        // Przyciski do operacji na kluczach
        Button generateKeyButton = new Button("Generuj nowe klucze");
        Button saveKeyButton = new Button("Zapisz klucze");
        Button loadKeyButton = new Button("Wczytaj klucze");

        // Przypisanie akcji
        generateKeyButton.setOnAction(e -> generateKeys());
        saveKeyButton.setOnAction(e -> saveKeys());
        loadKeyButton.setOnAction(e -> loadKeys());

        // Dodanie elementów do panelu
        topPanel.getChildren().addAll(keySizeLabel, keySizeComboBox, generateKeyButton, saveKeyButton, loadKeyButton);

        return topPanel;
    }

    private VBox createCenterPanel() {
        VBox centerPanel = new VBox(10);

        // Obszary wyświetlania komponentów kluczy - Zmiana: osobne pola dla n, e i d
        Label keysLabel = new Label("Komponenty klucza RSA:");

        // Wyświetlanie modułu (n)
        Label nKeyLabel = new Label("Moduł (n):");
        nKeyArea = new TextArea();
        nKeyArea.setPrefRowCount(2);
        nKeyArea.setEditable(false);
        nKeyArea.setWrapText(true);

        // Wyświetlanie wykładnika publicznego (e)
        Label eKeyLabel = new Label("Wykładnik publiczny (e):");
        eKeyArea = new TextArea();
        eKeyArea.setPrefRowCount(1);
        eKeyArea.setEditable(false);
        eKeyArea.setWrapText(true);

        // Wyświetlanie wykładnika prywatnego (d)
        Label dKeyLabel = new Label("Wykładnik prywatny (d):");
        dKeyArea = new TextArea();
        dKeyArea.setPrefRowCount(2);
        dKeyArea.setEditable(false);
        dKeyArea.setWrapText(true);

        // Pole tekstowe wejściowe
        Label inputLabel = new Label("Wejście:");
        inputTextArea = new TextArea();
        inputTextArea.setPrefRowCount(8);
        inputTextArea.setWrapText(true);

        // Pole tekstowe wyjściowe
        Label outputLabel = new Label("Wyjście:");
        outputTextArea = new TextArea();
        outputTextArea.setPrefRowCount(8);
        outputTextArea.setEditable(false);
        outputTextArea.setWrapText(true);

        centerPanel.getChildren().addAll(
            keysLabel,
            nKeyLabel, nKeyArea,
            eKeyLabel, eKeyArea,
            dKeyLabel, dKeyArea,
            inputLabel, inputTextArea,
            outputLabel, outputTextArea
        );
        return centerPanel;
    }

    // Utworzenie panelu dolnego
    private VBox createBottomPanel() {
        VBox bottomPanel = new VBox(10);

        // Etykieta wybranego pliku
        selectedFileLabel = new Label("Nie wybrano pliku");
        selectedFileLabel.setMaxWidth(Double.MAX_VALUE);

        // Przyciski radiowe do wyboru typu szyfrowania
        HBox radioBox = new HBox(10);
        ToggleGroup inputGroup = new ToggleGroup();
        fileRadio = new RadioButton("Plik");
        textRadio = new RadioButton("Tekst");
        fileRadio.setToggleGroup(inputGroup);
        textRadio.setToggleGroup(inputGroup);
        textRadio.setSelected(true);

        // Przyciski radiowe do wyboru typu klucza
        HBox keyTypeBox = new HBox(10);
        Label keyTypeLabel = new Label("Typ klucza do operacji:");
        ToggleGroup keyTypeGroup = new ToggleGroup();
        publicKeyRadio = new RadioButton("Klucz publiczny");
        privateKeyRadio = new RadioButton("Klucz prywatny");
        publicKeyRadio.setToggleGroup(keyTypeGroup);
        privateKeyRadio.setToggleGroup(keyTypeGroup);
        publicKeyRadio.setSelected(true);
        keyTypeBox.getChildren().addAll(keyTypeLabel, publicKeyRadio, privateKeyRadio);

        // Główne przyciski kontrolne
        Button openFileButton = new Button("Otwórz plik");
        Button encryptButton = new Button("Szyfruj");
        Button decryptButton = new Button("Deszyfruj");

        // Ustawienie akcji dla przycisków
        openFileButton.setOnAction(e -> openFile());
        encryptButton.setOnAction(e -> encrypt());
        decryptButton.setOnAction(e -> decrypt());
        fileRadio.setOnAction(e -> handleRadioChange());

        HBox buttonBox = new HBox(10);
        buttonBox.setAlignment(Pos.CENTER);
        buttonBox.getChildren().addAll(fileRadio, textRadio, openFileButton, encryptButton, decryptButton);

        bottomPanel.getChildren().addAll(selectedFileLabel, keyTypeBox, buttonBox);
        return bottomPanel;
    }

    private void generateKeys() {
        int keySize = getSelectedKeySize();
        rsa = new RSA(keySize);
        updateKeyDisplay();
        showAlert(Alert.AlertType.INFORMATION, "Pomyślnie wygenerowano nową parę kluczy RSA!");
    }

    private void updateKeyDisplay() {
        if (rsa == null) {
            nKeyArea.setText("Brak dostępnego klucza");
            eKeyArea.setText("Brak dostępnego klucza");
            dKeyArea.setText("Brak dostępnego klucza");
            return;
        }

        // Pobranie komponentów klucza jako ciągów znaków
        String[] keyComponents = extractKeyComponents();

        // Aktualizacja obszarów wyświetlania
        nKeyArea.setText(keyComponents[0]);  // n
        eKeyArea.setText(keyComponents[1]);  // e

        // Aktualizacja d tylko jeśli dostępne
        if (rsa.hasPrivateKey()) {
            dKeyArea.setText(keyComponents[2]);  // d
        } else {
            dKeyArea.setText("Klucz prywatny niedostępny");
        }
    }

    private String[] extractKeyComponents() {
        String[] components = new String[3]; // n, e, d

        // Wyodrębnienie komponentów z ciągów kluczy publicznego i prywatnego
        String publicKeyString = rsa.getPublicKeyString();
        String privateKeyString = rsa.hasPrivateKey() ? rsa.getPrivateKeyString() : "";

        // Wyodrębnienie n z ciągu klucza publicznego
        int nStart = publicKeyString.indexOf("n: ") + 3;
        int nEnd = publicKeyString.indexOf("\ne");
        components[0] = publicKeyString.substring(nStart, nEnd);

        // Wyodrębnienie e z ciągu klucza publicznego
        int eStart = publicKeyString.indexOf("e: ") + 3;
        components[1] = publicKeyString.substring(eStart);

        // Wyodrębnienie d z ciągu klucza prywatnego, jeśli dostępne
        if (rsa.hasPrivateKey() && privateKeyString.contains("d: ")) {
            int dStart = privateKeyString.indexOf("d: ") + 3;
            components[2] = privateKeyString.substring(dStart);
        } else {
            components[2] = "Niedostępny";
        }

        return components;
    }

    private void saveKeys() {
        if (rsa == null) {
            showAlert("Najpierw wygeneruj klucze!");
            return;
        }

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Zapisz klucz publiczny");
        fileChooser.setInitialFileName("rsa_public_key.key");
        File file = fileChooser.showSaveDialog(null);

        if (file != null) {
            try {
                rsa.saveKeyToFile(file.getPath());
                showAlert(Alert.AlertType.INFORMATION, "Klucz publiczny zapisany pomyślnie!");
            } catch (IOException e) {
                showAlert("Błąd podczas zapisywania klucza: " + e.getMessage());
            }
        }
    }

    private void loadKeys() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Wczytaj klucze");
        File file = fileChooser.showOpenDialog(null);

        if (file != null) {
            try {
                rsa = RSA.loadKeyFromFile(file.getPath());
                updateKeyDisplay();
                showAlert(Alert.AlertType.INFORMATION, "Klucze wczytane pomyślnie!");
            } catch (Exception e) {
                showAlert("Błąd podczas wczytywania kluczy: " + e.getMessage());
            }
        }
    }

    private void openFile() {
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showOpenDialog(null);
        if (file != null) {
            selectedFile = file;
            selectedFileLabel.setText("Wybrany plik: " + file.getName());
            inputTextArea.clear();
        }
    }

    private void encrypt() {
        try {
            if (rsa == null) {
                showAlert("Najpierw wygeneruj lub wczytaj klucze!");
                return;
            }

            if (fileRadio.isSelected() && selectedFile == null) {
                showAlert("Najpierw wybierz plik!");
                return;
            }

            // Dla RSA używamy klucza publicznego do szyfrowania
            if (privateKeyRadio.isSelected()) {
                showAlert("Szyfrowanie wymaga klucza publicznego. Przełączam na klucz publiczny.");
                publicKeyRadio.setSelected(true);
            }

            performEncryption();
        } catch (Exception ex) {
            showAlert("Błąd szyfrowania: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    private void decrypt() {
        try {
            if (rsa == null) {
                showAlert("Najpierw wygeneruj lub wczytaj klucze!");
                return;
            }

            if (!rsa.hasPrivateKey()) {
                showAlert("Klucz prywatny niedostępny. Deszyfrowanie nie jest możliwe tylko z kluczem publicznym.");
                return;
            }

            if (fileRadio.isSelected() && selectedFile == null) {
                showAlert("Najpierw wybierz plik!");
                return;
            }

            // Dla RSA używamy klucza prywatnego do deszyfrowania
            if (publicKeyRadio.isSelected()) {
                showAlert("Deszyfrowanie wymaga klucza prywatnego. Przełączam na klucz prywatny.");
                privateKeyRadio.setSelected(true);
            }

            performDecryption();
        } catch (Exception ex) {
            showAlert("Błąd deszyfrowania: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    private void performEncryption() throws IOException {
        if (textRadio.isSelected()) {
            String inputText = inputTextArea.getText();
            if (inputText.isEmpty()) {
                showAlert("Wprowadź tekst do zaszyfrowania");
                return;
            }

            try {
                byte[] inputBytes = inputText.getBytes();
                byte[] encrypted = rsa.encrypt(inputBytes);
                outputTextArea.setText(bytesToHex(encrypted));
                showAlert(Alert.AlertType.INFORMATION, "Tekst zaszyfrowany pomyślnie!");
            } catch (Exception ex) {
                showAlert("Błąd szyfrowania: " + ex.getMessage());
            }
        } else {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Zapisz zaszyfrowany plik");
            fileChooser.setInitialFileName(selectedFile.getName() + ".enc");
            File file = fileChooser.showSaveDialog(null);

            if (file != null) {
                try {
                    byte[] fileBytes = rsa.readFile(selectedFile.getPath());
                    byte[] encrypted = rsa.encrypt(fileBytes);
                    rsa.writeFile(file.getPath(), encrypted);
                    outputTextArea.setText("Plik zaszyfrowany pomyślnie i zapisany do: " + file.getPath());
                } catch (Exception ex) {
                    showAlert("Błąd szyfrowania pliku: " + ex.getMessage());
                    ex.printStackTrace();
                }
            }
        }
    }

    private void performDecryption() throws IOException {
        if (textRadio.isSelected()) {
            String inputHex = inputTextArea.getText().trim();
            if (inputHex.isEmpty()) {
                showAlert("Wprowadź zaszyfrowany tekst (w formacie szesnastkowym) do odszyfrowania");
                return;
            }

            try {
                byte[] encryptedBytes = hexStringToByteArray(inputHex);
                if (encryptedBytes.length < 8) {
                    showAlert("Dane wejściowe są zbyt krótkie, aby były poprawnymi zaszyfrowanymi danymi");
                    return;
                }
                
                outputTextArea.setText("Deszyfrowanie danych...");
                byte[] decrypted = rsa.decrypt(encryptedBytes);
                outputTextArea.setText(new String(decrypted));
                showAlert(Alert.AlertType.INFORMATION, "Tekst odszyfrowany pomyślnie!");
            } catch (IllegalArgumentException ex) {
                showAlert("Nieprawidłowy format szesnastkowy: " + ex.getMessage());
            } catch (Exception ex) {
                showAlert("Błąd deszyfrowania: " + ex.getMessage());
                ex.printStackTrace();
                outputTextArea.setText("Deszyfrowanie nie powiodło się: " + ex.getMessage());
            }
        } else {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Zapisz odszyfrowany plik");
            String originalName = selectedFile.getName();
            if (originalName.endsWith(".enc")) {
                originalName = originalName.substring(0, originalName.length() - 4);
            }
            fileChooser.setInitialFileName("dec_" + originalName);
            File file = fileChooser.showSaveDialog(null);

            if (file != null) {
                try {
                    outputTextArea.setText("Odczytywanie zaszyfrowanego pliku...");

                    byte[] fileBytes = rsa.readFile(selectedFile.getPath());
                    if (fileBytes.length < 8) {
                        showAlert("Wybrany plik jest zbyt mały, aby zawierać poprawne zaszyfrowane dane");
                        return;
                    }
                    
                    outputTextArea.setText("Deszyfrowanie pliku: " + selectedFile.getName() +
                                          " (rozmiar: " + fileBytes.length + " bajtów)");

                    byte[] decrypted = rsa.decrypt(fileBytes);

                    if (decrypted == null) {
                        outputTextArea.setText("Deszyfrowanie zwróciło wynik null. Oznacza to poważny problem z procesem deszyfrowania.");
                        showAlert(Alert.AlertType.ERROR, "Deszyfrowanie nie powiodło się: Wynik null");
                        return;
                    }

                    if (decrypted.length == 0) {
                        showAlert(Alert.AlertType.WARNING, "Ostrzeżenie: Deszyfrowanie dało w wyniku pusty plik. Może to wskazywać na problem z zaszyfrowanymi danymi lub kluczem.");
                        outputTextArea.setText(outputTextArea.getText() + "\nDeszyfrowanie dało w wyniku pusty plik!");
                    } else {
                        outputTextArea.setText(outputTextArea.getText() + 
                            "\nRozmiar odszyfrowanych danych: " + decrypted.length + " bajtów" +
                            "\nZapisywanie do pliku: " + file.getPath());
                        
                        rsa.writeFile(file.getPath(), decrypted);
                        
                        outputTextArea.setText(outputTextArea.getText() + 
                            "\nPlik odszyfrowany pomyślnie!" +
                            "\nRozmiar pliku: " + file.length() + " bajtów");
                            
                        showAlert(Alert.AlertType.INFORMATION, "Plik odszyfrowany pomyślnie!\nRozmiar pliku: " + file.length() + " bajtów");
                    }
                } catch (Exception ex) {
                    ex.printStackTrace();
                    outputTextArea.setText("Deszyfrowanie nie powiodło się: " + ex.getMessage() + 
                                         "\nZobacz konsolę dla pełnego stosu wywołań");
                    showAlert(Alert.AlertType.ERROR, "Błąd deszyfrowania pliku: " + ex.getMessage());
                }
            }
        }
    }

    private void handleRadioChange() {
        if (textRadio.isSelected()) {
            selectedFile = null;
            selectedFileLabel.setText("Nie wybrano pliku");
        }
    }

    private void showAlert(String message) {
        Alert alert = new Alert(Alert.AlertType.WARNING);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    private void showAlert(Alert.AlertType type, String message) {
        Alert alert = new Alert(type);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    private int getSelectedKeySize() {
        String selected = keySizeComboBox.getValue();
        return switch (selected) {
            case "1024 bits" -> 1024;
            case "4096 bits" -> 4096;
            default -> 2048;
        };
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private static byte[] hexStringToByteArray(String hex) {
        hex = hex.replaceAll("\\s+", "");
        int len = hex.length();

        if (len % 2 != 0) {
            throw new IllegalArgumentException("Ciąg szesnastkowy musi mieć parzystą długość");
        }

        byte[] data = new byte[len / 2];
        try {
            for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                        + Character.digit(hex.charAt(i + 1), 16));
            }
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Nieprawidłowy znak szesnastkowy");
        }
        return data;
    }

    // Metoda główna
    public static void main(String[] args) {
        launch(args);
    }
}
