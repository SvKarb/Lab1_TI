// Константы алфавитов
const ENGLISH_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const RUSSIAN_ALPHABET = 'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ';

// Фильтрация (используется внутри алгоритмов для гарантии, но теперь входные данные уже чистые)
function filterEnglish(text) {
    return text.toUpperCase().split('').filter(ch => ENGLISH_ALPHABET.includes(ch)).join('');
}
function filterRussian(text) {
    return text.toUpperCase().split('').filter(ch => RUSSIAN_ALPHABET.includes(ch)).join('');
}

// Столбцовый метод
function columnarEncrypt(plain, key) {
    const cleanPlain = filterEnglish(plain); 
    if (!cleanPlain) return { result: '', matrixData: null };
    const cols = key.length;
    const rows = Math.ceil(cleanPlain.length / cols);
    const keyUpper = key.toUpperCase().split('');
    const indices = Array.from({ length: cols }, (_, i) => i);
    indices.sort((a, b) => {
        if (keyUpper[a] < keyUpper[b]) return -1;
        if (keyUpper[a] > keyUpper[b]) return 1;
        return a - b;
    });
    const table = [];
    for (let i = 0; i < rows; i++) {
        const row = [];
        for (let j = 0; j < cols; j++) {
            const index = i * cols + j;
            row.push(index < cleanPlain.length ? cleanPlain[index] : null);
        }
        table.push(row);
    }
    let cipher = '';
    for (const colIdx of indices) {
        for (let r = 0; r < rows; r++) {
            if (table[r][colIdx] !== null) cipher += table[r][colIdx];
        }
    }
    return {
        result: cipher,
        matrixData: { type: 'encrypt', key: keyUpper, sortedIndices: indices, table, rows, cols }
    };
}

function columnarDecrypt(cipher, key) {
    const cleanCipher = filterEnglish(cipher);
    if (!cleanCipher) return { result: '', matrixData: null };
    const cols = key.length;
    const total = cleanCipher.length;
    const baseRows = Math.floor(total / cols); // минимальное количество строк в столбце
    const remainder = total % cols; // сколько столбцов имеют на одну строку больше

    // Длины столбцов в исходном порядке (по индексам столбцов)
    const colLengths = Array(cols).fill(baseRows);
    for (let i = 0; i < remainder; i++) {
        colLengths[i] = baseRows + 1;
    }

    const keyUpper = key.toUpperCase().split('');
    const indices = Array.from({ length: cols }, (_, i) => i);
    // Сортируем индексы по ключу, получаем порядок считывания столбцов при шифровании
    indices.sort((a, b) => {
        if (keyUpper[a] < keyUpper[b]) return -1;
        if (keyUpper[a] > keyUpper[b]) return 1;
        return a - b;
    });

    // Распределяем символы шифртекста по столбцам в порядке indices
    const columns = Array.from({ length: cols }, () => []);
    let pos = 0;
    for (const colIdx of indices) {
        const len = colLengths[colIdx];
        columns[colIdx] = cleanCipher.substr(pos, len).split('');
        pos += len;
    }

    // Общее количество строк в таблице
    const totalRows = baseRows + (remainder > 0 ? 1 : 0);

    // Собираем текст по строкам в исходном порядке столбцов 
    let plain = '';
    for (let r = 0; r < totalRows; r++) {
        for (let c = 0; c < cols; c++) {
            if (r < columns[c].length) {
                plain += columns[c][r];
            }
        }
    }

    return {
        result: plain,
        matrixData: { type: 'decrypt', key: keyUpper, sortedIndices: indices, columns, rows: totalRows, cols, colLengths }
    };
}

// Виженер с прогрессивным ключом
function vigenereEncrypt(plain, key) {
    const cleanPlain = filterRussian(plain);
    if (!cleanPlain) return { result: '', keyStream: [] };
    const keyClean = filterRussian(key);
    if (!keyClean) throw new Error('Внутренняя ошибка: ключ не содержит русских букв');
    
    const keyLen = keyClean.length;
    const keyStream = [];
    let cipher = '';
    
    for (let i = 0; i < cleanPlain.length; i++) {
        const pIdx = RUSSIAN_ALPHABET.indexOf(cleanPlain[i]);
        const keyChar = keyClean[i % keyLen];
        const keyIdx = RUSSIAN_ALPHABET.indexOf(keyChar);
        const shift = Math.floor(i / keyLen);
        const effectiveKeyIdx = (keyIdx + shift) % RUSSIAN_ALPHABET.length;
        const effectiveKeyChar = RUSSIAN_ALPHABET[effectiveKeyIdx];
        keyStream.push(effectiveKeyChar);
        
        const cIdx = (pIdx + effectiveKeyIdx) % RUSSIAN_ALPHABET.length;
        cipher += RUSSIAN_ALPHABET[cIdx];
    }
    return { result: cipher, keyStream };
}

function vigenereDecrypt(cipher, key) {
    const cleanCipher = filterRussian(cipher);
    if (!cleanCipher) return { result: '', keyStream: [] };
    const keyClean = filterRussian(key);
    if (!keyClean) throw new Error('Внутренняя ошибка: ключ не содержит русских букв');
    
    const keyLen = keyClean.length;
    const keyStream = [];
    let plain = '';
    
    for (let i = 0; i < cleanCipher.length; i++) {
        const cIdx = RUSSIAN_ALPHABET.indexOf(cleanCipher[i]);
        const keyChar = keyClean[i % keyLen];
        const keyIdx = RUSSIAN_ALPHABET.indexOf(keyChar);
        const shift = Math.floor(i / keyLen);
        const effectiveKeyIdx = (keyIdx + shift) % RUSSIAN_ALPHABET.length;
        const effectiveKeyChar = RUSSIAN_ALPHABET[effectiveKeyIdx];
        keyStream.push(effectiveKeyChar);
        
        const pIdx = (cIdx - effectiveKeyIdx + RUSSIAN_ALPHABET.length) % RUSSIAN_ALPHABET.length;
        plain += RUSSIAN_ALPHABET[pIdx];
    }
    return { result: plain, keyStream };
}

// Элементы интерфейса
const algorithmRadios = document.getElementsByName('algorithm');
const keyInput = document.getElementById('key');
const inputText = document.getElementById('input-text');
const outputText = document.getElementById('output-text');
const encryptBtn = document.getElementById('encrypt-btn');
const decryptBtn = document.getElementById('decrypt-btn');
const loadFileBtn = document.getElementById('load-file-btn');
const fileInput = document.getElementById('file-input');
const downloadBtn = document.getElementById('download-btn');
const messageDiv = document.getElementById('message');
const showMatrixCheckbox = document.getElementById('show-matrix');
const showVigenereTableCheckbox = document.getElementById('show-vigenere-table');
const matrixView = document.getElementById('matrix-view');

function getCurrentAlgorithm() {
    for (const radio of algorithmRadios) if (radio.checked) return radio.value;
    return 'columnar';
}

// Проверка ключа: только буквы соответствующего алфавита
function validateKey(algorithm, key) {
    if (!key) return 'Ключ не может быть пустым';
    const upperKey = key.toUpperCase();
    const alphabet = algorithm === 'columnar' ? ENGLISH_ALPHABET : RUSSIAN_ALPHABET;
    for (let ch of upperKey) {
        if (!alphabet.includes(ch)) {
            return `Ключ содержит недопустимые символы. Разрешены только ${algorithm === 'columnar' ? 'английские' : 'русские'} буквы.`;
        }
    }
    return null;
}

// Проверка текста: только буквы соответствующего алфавита
function validateText(algorithm, text) {
    if (!text) return null; 
    const upperText = text.toUpperCase();
    const alphabet = algorithm === 'columnar' ? ENGLISH_ALPHABET : RUSSIAN_ALPHABET;
    for (let ch of upperText) {
        if (!alphabet.includes(ch)) {
            return `Текст содержит недопустимые символы. Разрешены только ${algorithm === 'columnar' ? 'английские' : 'русские'} буквы.`;
        }
    }
    return null;
}

// Отображение матрицы для столбцового метода
function displayColumnarMatrix(matrixData) {
    if (!matrixData || !showMatrixCheckbox.checked) {
        matrixView.innerHTML = '';
        return;
    }
    const { type, key, sortedIndices, rows, cols } = matrixData;
    const rank = new Array(cols);
    sortedIndices.forEach((colIdx, pos) => { rank[colIdx] = pos + 1; });

    let html = '<h3>Промежуточная матрица (столбцовый метод)</h3><table class="matrix-table"><tr>';
    for (let c = 0; c < cols; c++) html += `<th>${key[c]}</th>`;
    html += '</tr><tr>';
    for (let c = 0; c < cols; c++) html += `<td style="font-weight:bold;background:#e0e0e0;">${rank[c]}</td>`;
    html += '</tr>';

    const maxRows = 10;
    if (type === 'encrypt') {
        const table = matrixData.table;
        const displayRows = Math.min(rows, maxRows);
        for (let r = 0; r < displayRows; r++) {
            html += '<tr>';
            for (let c = 0; c < cols; c++) {
                const val = table[r][c];
                html += `<td>${val !== null ? val : ' '}</td>`;
            }
            html += '</tr>';
        }
        if (rows > maxRows) html += `<tr><td colspan="${cols}" style="text-align:center;">... и ещё ${rows - maxRows} строк</td></tr>`;
        html += '</table><p class="matrix-info">Порядок считывания: по номерам столбцов</p>';
    } else {
        const columns = matrixData.columns;
        const displayRows = Math.min(rows, maxRows);
        for (let r = 0; r < displayRows; r++) {
            html += '<tr>';
            for (let c = 0; c < cols; c++) {
                const val = (r < columns[c].length) ? columns[c][r] : null;
                html += `<td>${val !== null ? val : ' '}</td>`;
            }
            html += '</tr>';
        }
        if (rows > maxRows) html += `<tr><td colspan="${cols}" style="text-align:center;">... и ещё ${rows - maxRows} строк</td></tr>`;
        html += '</table><p class="matrix-info">Чтение по строкам (слева направо) восстанавливает текст</p>';
    }
    matrixView.innerHTML = html;
}

// Отображение таблицы для Виженера
function displayVigenereTable(plainText, keyStream, cipherText) {
    if (!showVigenereTableCheckbox.checked) {
        matrixView.innerHTML = '';
        return;
    }
    if (!plainText || !keyStream || !cipherText) return;
    
    let html = '<h3>Таблица соответствия (Виженер, прогрессивный ключ)</h3>';
    html += '<table class="matrix-table">';
    // Строка исходного текста
    html += '<tr>';
    for (let ch of plainText) {
        html += `<td>${ch}</td>`;
    }
    html += '</tr>';
    // Строка ключа
    html += '<tr>';
    for (let ch of keyStream) {
        html += `<td>${ch}</td>`;
    }
    html += '</tr>';
    // Строка результата
    html += '<tr>';
    for (let ch of cipherText) {
        html += `<td>${ch}</td>`;
    }
    html += '</tr>';
    html += '</table>';
    html += '<p class="matrix-info">Верхний ряд — исходный текст, средний — прогрессивный ключ, нижний — результат</p>';
    matrixView.innerHTML = html;
}

// Основная функция обработки
function process(mode) {
    const algorithm = getCurrentAlgorithm();
    const key = keyInput.value.trim();
    const text = inputText.value;

    // Проверка ключа
    const keyError = validateKey(algorithm, key);
    if (keyError) {
        messageDiv.textContent = keyError;
        messageDiv.className = 'error';
        matrixView.innerHTML = '';
        return;
    }

    // Проверка текста
    if (!text) {
        messageDiv.textContent = 'Введите текст или загрузите файл';
        messageDiv.className = 'error';
        matrixView.innerHTML = '';
        return;
    }
    const textError = validateText(algorithm, text);
    if (textError) {
        messageDiv.textContent = textError;
        messageDiv.className = 'error';
        matrixView.innerHTML = '';
        return;
    }

    try {
        let result = '';
        let matrixData = null;
        let keyStream = [];
        let cleanText = '';
        
        if (algorithm === 'columnar') {
            const res = mode === 'encrypt' ? columnarEncrypt(text, key) : columnarDecrypt(text, key);
            result = res.result;
            matrixData = res.matrixData;
            if (!result) {
                messageDiv.textContent = 'Внутренняя ошибка: не удалось обработать текст';
                messageDiv.className = 'error';
                outputText.value = '';
                matrixView.innerHTML = '';
                return;
            }
            displayColumnarMatrix(matrixData);
        } else {
            // Виженер
            if (mode === 'encrypt') {
                const res = vigenereEncrypt(text, key);
                result = res.result;
                keyStream = res.keyStream;
                cleanText = filterRussian(text); // для отображения
            } else {
                const res = vigenereDecrypt(text, key);
                result = res.result;
                keyStream = res.keyStream;
                cleanText = filterRussian(text); // для отображения
            }
            if (!result) {
                messageDiv.textContent = 'Внутренняя ошибка: не удалось обработать текст';
                messageDiv.className = 'error';
                outputText.value = '';
                matrixView.innerHTML = '';
                return;
            }
            displayVigenereTable(cleanText, keyStream, result);
        }
        outputText.value = result;
        messageDiv.textContent = 'Операция выполнена успешно';
        messageDiv.className = 'info';
    } catch (e) {
        messageDiv.textContent = 'Ошибка: ' + e.message;
        messageDiv.className = 'error';
        matrixView.innerHTML = '';
    }
}

encryptBtn.addEventListener('click', () => process('encrypt'));
decryptBtn.addEventListener('click', () => process('decrypt'));

loadFileBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
        inputText.value = event.target.result;
        messageDiv.textContent = `Файл "${file.name}" загружен`;
        messageDiv.className = 'info';
        fileInput.value = '';
    };
    reader.onerror = () => {
        messageDiv.textContent = 'Ошибка чтения файла';
        messageDiv.className = 'error';
    };
    reader.readAsText(file, 'UTF-8');
});

downloadBtn.addEventListener('click', () => {
    const result = outputText.value;
    if (!result) {
        messageDiv.textContent = 'Нет результата для сохранения';
        messageDiv.className = 'error';
        return;
    }
    const blob = new Blob([result], { type: 'text/plain;charset=utf-8' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'result.txt';
    link.click();
    URL.revokeObjectURL(link.href);
    messageDiv.textContent = 'Файл сохранён';
    messageDiv.className = 'info';
});

for (const radio of algorithmRadios) {
    radio.addEventListener('change', () => matrixView.innerHTML = '');
}

const clearKeyBtn = document.getElementById('clear-key-btn');
const clearTextBtn = document.getElementById('clear-text-btn');

clearKeyBtn.addEventListener('click', () => {
    keyInput.value = '';
    messageDiv.textContent = '';
    messageDiv.className = '';
    matrixView.innerHTML = '';
});

clearTextBtn.addEventListener('click', () => {
    inputText.value = '';
    messageDiv.textContent = '';
    messageDiv.className = '';
    matrixView.innerHTML = '';
});