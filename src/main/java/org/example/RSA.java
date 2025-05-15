package org.example;
import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
    private BigInteger n;
    private BigInteger e;
    private BigInteger d;
    private BigInteger p;
    private BigInteger q;
    private int keySize; // key size in bits

    //Konstruktor z rozmiarem klucza
    public RSA(int keySize) {
        this.keySize = keySize;
        generateKeyPair();
    }

    //Konstruktor z parametrami kluczy
    public RSA(BigInteger n, BigInteger e, BigInteger d) {
        this.n = n;
        this.e = e;
        this.d = d;
        this.keySize = n.bitLength();
    }

    //Generowanie kluczy
    private void generateKeyPair() {
        SecureRandom random = new SecureRandom();

        //Generowanie dwóch różnych liczb pierwszych p i q
        p = BigInteger.probablePrime(keySize / 2, random);
        do {
            q = BigInteger.probablePrime(keySize / 2, random);
        } while (p.equals(q));

        //Obliczanie n = p * q
        n = p.multiply(q);

        //Obliczenie phi(n) = (p-1)(q-1)
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        //Upewnijmy się, że e jest mniejsze od phi(n)
        int eBitLength = phi.bitLength() / 2; // Używamy połowy bitów phi dla e
        eBitLength = Math.max(eBitLength, 17); // Minimum 17 bitów
        
        //Generowanie losowej nieparzystej wartości e
        do {
            e = new BigInteger(eBitLength, random);
            // Upewniamy się, że e jest nieparzyste
            if (e.testBit(0) == false) { // Jeśli parzyste
                e = e.add(BigInteger.ONE); // Dodajemy 1, aby było nieparzyste
            }
            // Upewniamy się, że e > 1 i e < phi(n)
        } while (e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(phi) >= 0 || phi.gcd(e).compareTo(BigInteger.ONE) > 0);

        //Obliczanie d, odwrotności e modulo phi(n), tak aby d * e ≡ 1 (mod phi(n))
        d = e.modInverse(phi);
    }

    //Wczytanie pliku jako tablicy bajtów
    public byte[] readFile(String filePath) throws IOException {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            //Pobieramy rozmiar pliku w bajtach
            long fileSize = new File(filePath).length();
            //Sprawdzamy, czy plik nie jest zbyt duży aby moc wczytac go do pojedynczej tablicy bajtów
            if (fileSize > Integer.MAX_VALUE) {
                throw new IOException("File too large, maximum size is " + Integer.MAX_VALUE + " bytes");
            }

            //Tworzymy tablicę bajtów o odpowiednim rozmiarze
            byte[] data = new byte[(int)fileSize];
            int bytesRead = 0;
            int read;

            //Wczytujemy bajty do tablicy data zaczynajac od pozycji bytesRead, w ilosci data.length - bytesRead
            while (bytesRead < data.length && (read = fis.read(data, bytesRead, data.length - bytesRead)) != -1) {
                bytesRead += read;
            }

            //Sprawdzamy, czy udało się wczytać cały plik
            if (bytesRead < data.length) {
                throw new IOException("Could not read entire file, only read " + bytesRead + " of " + data.length + " bytes");
            }

            return data;
        }
    }

    //Dodajemy padding PKCS#1 v1.5 do danych
    private byte[] addPKCS1Padding(byte[] data, int blockSize) {
        // PKCS#1 v1.5 padding format: 0x00 || 0x02 || r || 0x00 || m
        byte[] padded = new byte[blockSize];
        SecureRandom random = new SecureRandom();

        padded[0] = 0x00;
        padded[1] = 0x02;

        //Obliczamy długość randomowych bajtów
        int rLength = blockSize - data.length - 3;

        //Uzupełniamy r losowymi bajtami
        for (int i = 2; i < 2 + rLength; i++) {
            byte randomByte;
            do {
                randomByte = (byte) random.nextInt(256);
            } while (randomByte == 0);
            padded[i] = randomByte;
        }

        //Dodajemy separator 0x00
        padded[2 + rLength] = 0x00;

        //Kopiujemy dane do padded
        System.arraycopy(data, 0, padded, blockSize - data.length, data.length);

        return padded;
    }

    //Usuwamy padding PKCS#1 v1.5 z danych
    private byte[] removePKCS1Padding(byte[] paddedData, int expectedBlockSize) {
        //Jeżeli nie mamy danych do usunięcia paddingu to zwracamy pustą tablicę
        if (paddedData == null || paddedData.length == 0) {
            return new byte[0];
        }

        //Jeżeli długość danych jest mniejsza niż oczekiwana długość bloku to dopełniamy do oczekiwanej długości
        byte[] normalized;
        if (paddedData.length < expectedBlockSize) {
            normalized = new byte[expectedBlockSize];
            System.arraycopy(paddedData, 0, normalized, expectedBlockSize - paddedData.length, paddedData.length);
        } else {
            //Usuwamy wiodące zera (czasami są one dodawane przez BigInteger)
            int startOffset = 0;
            while (startOffset < paddedData.length - 1 && paddedData[startOffset] == 0) {
                startOffset++;
            }
            //Jeżeli pierwszy bajt jest ujemny to przesuwamy offset o 1 aby nie był ujemny
            if (paddedData[startOffset] < 0) {
                startOffset--;
            }

            //Jeżeli offset jest większy od 0 to kopiujemy dane do nowej tablicy juz bez wiodących zer
            if (startOffset > 0) {
                normalized = new byte[paddedData.length - startOffset];
                System.arraycopy(paddedData, startOffset, normalized, 0, normalized.length);
            } else {
                normalized = paddedData;
            }
        }
        //Szukamy pierwszego niezerowego bajtu
        int startIdx = 0;
        //Jeżeli mamy same zera to przesuwamy startIdx do pierwszego niezerowego bajtu
        while (startIdx < normalized.length && normalized[startIdx] == 0) {
            startIdx++;
        }

        //Szukamy separatora 0x02
        if (startIdx >= normalized.length || normalized[startIdx] != 0x02) {
            //Jeżeli nie ma separatora to zwracamy oryginalne dane uznajac padding za niepoprawny
            return normalized;
        }

        //Szukamy separatora 0x00
        int separatorIdx = startIdx + 1;
        while (separatorIdx < normalized.length && normalized[separatorIdx] != 0x00) {
            separatorIdx++;
        }

        //Jeżeli nie ma separatora 0x00 to zwracamy oryginalne dane uznajac padding za niepoprawny
        if (separatorIdx >= normalized.length - 1) {
            return normalized;
        }

        //Jeżeli mamy separator 0x00 to kopiujemy dane do nowej tablicy
        int dataLength = normalized.length - separatorIdx - 1;
        byte[] result = new byte[dataLength];
        System.arraycopy(normalized, separatorIdx + 1, result, 0, dataLength);
        return result;
    }

    // Szyfrujemy wiadomość jako tablicę bajtów
    public byte[] encrypt(byte[] message) {
        //Maksymalny rozmiar bloku do zaszyfrowania w bajtach minus 11 dla paddingu
        int maxBlockSize = (n.bitLength() / 8) - 11;

        //ByteArrayOutputStream zapisuje dane binarne do bufora w pamieci
        //DataOutputStream zapisuje w łatwy sposób dane do ByteArrayOutputStream w formacie binarnym
        try (ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
             DataOutputStream dataOut = new DataOutputStream(byteOut)) {

            //Zapisujemy długość wiadomości
            dataOut.writeInt(message.length);

            //Przesunięcie się po wiadomości o maksymalny rozmiar bloku
            for (int offset = 0; offset < message.length; offset += maxBlockSize) {
                //Jesli zostalo mniej bajtow niz maks rozmiar bloku to bierzemy tyle ile jest
                int blockSize = Math.min(maxBlockSize, message.length - offset);
                byte[] block = new byte[blockSize];
                //Kopiujemy bajty z wiadomości do bloku
                System.arraycopy(message, offset, block, 0, blockSize);

                //Dodajemy padding
                byte[] paddedBlock = addPKCS1Padding(block, n.bitLength() / 8);
                //Szyfrujemy blok
                BigInteger encrypted = new BigInteger(1, paddedBlock).modPow(e, n);
                //Zapisujemy zaszyfrowany blok do strumienia upewniając się, że ma odpowiednią długość (musi być równa długości n)
                dataOut.write(toFixedLength(encrypted.toByteArray(), n.bitLength() / 8));
            }
            return byteOut.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Error during encryption", e);
        }
    }

    //Deszyfrujemy wiadomość jako tablicę bajtów
    public byte[] decrypt(byte[] encryptedMessage) {
        //Sprawdzamy, czy mamy klucz prywatny
        if (!hasPrivateKey()) {
            throw new IllegalStateException("Private key is required for decryption");
        }

        //ByteArrayInputStream odczytuje bajty z tablicy encryptedMessage
        //DataInputStream odczytuje dane binarne z ByteArrayInputStream (latwiejsze niż ręczne parsowanie)
        try (ByteArrayInputStream byteIn = new ByteArrayInputStream(encryptedMessage);
             DataInputStream dataIn = new DataInputStream(byteIn)) {

            //Odczytujemy długość oryginalnej wiadomości
            int originalLength = dataIn.readInt();

            //Sprawdzamy, czy długość jest poprawna -
            if (originalLength <= 0 || originalLength > 1000000000) {
                throw new IOException("Invalid data format or corrupted encrypted file");
            }

            //Ustalamy rozmiar bloku do deszyfrowania (powinien być równy długości n)
            int blockSize = n.bitLength() / 8;
            //Tworzymy ByteArrayOutputStream do przechowywania odszyfrowanych danych
            ByteArrayOutputStream result = new ByteArrayOutputStream(originalLength);
            //Tworzymy tablicę bajtów do przechowywania odszyfrowanego bloku
            byte[] encryptedBlock = new byte[blockSize];

            //Dopoki jest jakis blok do odczytania i nie przekroczyliśmy oryginalnej długości wiadomosci
            while (byteIn.available() >= blockSize && result.size() < originalLength) {
                //Odczytujemy zaszyfrowany blok bajtów i zapisujemy go do tablicy
                dataIn.readFully(encryptedBlock);

                //Konwersja zaszyfrowanego bloku do BigInteger i odszyfrowanie
                BigInteger encryptedBigInt = new BigInteger(1, encryptedBlock);
                BigInteger decryptedBigInt = encryptedBigInt.modPow(d, n);

                //Konwersja odszyfrowanego bloku do tablicy bajtów
                byte[] decryptedBlockWithPadding = decryptedBigInt.toByteArray();

                //Usuwamy padding z odszyfrowanego bloku
                byte[] unpaddedBlock = removePKCS1Padding(decryptedBlockWithPadding, blockSize);

                //Jezeli odszyfrowany blok nie jest pusty i zawiera jakies bajty
                if (unpaddedBlock.length > 0) {
                    //Zapisujemy tyle bajtów do wyniku ile jest w oryginalnej wiadomości
                    int bytesToWrite = Math.min(unpaddedBlock.length, originalLength - result.size());
                    result.write(unpaddedBlock, 0, bytesToWrite);
                }
            }

            //Ostateczne sprawdzenie długości wyniku
            byte[] finalResult = result.toByteArray();
            //Jeżeli wynik jest dłuższy niż oryginalna długość, to przycinamy go
            if (finalResult.length > originalLength) {
                byte[] trimmed = new byte[originalLength];
                System.arraycopy(finalResult, 0, trimmed, 0, originalLength);
                return trimmed;
            }
            return finalResult;
        } catch (IOException e) {
            throw new RuntimeException("Error during decryption: " + e.getMessage(), e);
        }
    }

    //Poprawa długosci tablicy bajtów
    private byte[] toFixedLength(byte[] data, int length) {
        //Czasami BigInteger dodaje 0x00 na początku (znak liczby) jeśli tak jest to przesuwamy offset o 1
        int offset = (data.length > length && data[0] == 0) ? 1 : 0;

        //Tworzymy tablicę docelową o odpowiedniej długości
        byte[] result = new byte[length];
        //Jeżeli mamy mniej bajtów niż oczekiwana długość to dopełniamy zerami
        if (data.length - offset <= length) {
            int padding = length - (data.length - offset);
            System.arraycopy(data, offset, result, padding, data.length - offset);
        } else {
            System.arraycopy(data, offset, result, 0, length);
        }
        return result;
    }

    //Zapisujemy tablicę bajtów do pliku
    public void writeFile(String filePath, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(data);
            fos.flush();
        }
    }

    //Zapisujemy klucz do pliku z nagłówkiem
    public void saveKeyToFile(String filePath) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath))) {
            //Zapisujemy nagłówek z wersją klucza
            oos.writeUTF("RSA_KEY_FORMAT_V1");
            oos.writeObject(n);
            oos.writeObject(e);

            oos.writeBoolean(hasPrivateKey());
            if (hasPrivateKey()) {
                oos.writeObject(d);
            }
        }
    }

    //Wczytujemy klucz z pliku z nagłówkiem
    public static RSA loadKeyFromFile(String filePath) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            String format;
            try {
                format = ois.readUTF();
                if (!format.startsWith("RSA_KEY_FORMAT")) {
                    throw new IOException("Invalid key file format");
                }
            } catch (IOException ex) {
                //Bez nagłówka, próbujemy wczytać klucz w formacie starszym
                try (ObjectInputStream legacyOis = new ObjectInputStream(new FileInputStream(filePath))) {
                    BigInteger n = (BigInteger) legacyOis.readObject();
                    BigInteger e = (BigInteger) legacyOis.readObject();
                    return new RSA(n, e, null); // Public key only
                }
            }

            //Jeżeli mamy nagłówek to wczytujemy klucz
            BigInteger n = (BigInteger) ois.readObject();
            BigInteger e = (BigInteger) ois.readObject();

            //Jeżeli mamy klucz prywatny to wczytujemy go
            BigInteger d = null;
            try {
                boolean hasPrivateKey = ois.readBoolean();
                if (hasPrivateKey) {
                    d = (BigInteger) ois.readObject();
                }
            } catch (EOFException ex) {
                //Brak klucza prywatnego
            }

            return new RSA(n, e, d); // Public key only
        }
    }
    //Sprawdzamy czy mamy klucz prywatny
    public boolean hasPrivateKey() {
        return d != null;
    }

    //Tworzymy ciąg znaków do wyswietlenia klucza publicznego
    public String getPublicKeyString() {
        return "n: " + n.toString(16) + "\ne: " + e.toString(16);
    }

    //Tworzymy ciąg znaków do wyswietlenia klucza prywatnego
    public String getPrivateKeyString() {
        if (!hasPrivateKey()) {
            return "Private key not available";
        }
        return "n: " + n.toString(16) + "\nd: " + d.toString(16);
    }
}

