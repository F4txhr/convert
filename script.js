// Data untuk konversi
const exchangeRates = {
    USD: { IDR: 15000, EUR: 0.85, GBP: 0.73, JPY: 110, CNY: 6.45 },
    IDR: { USD: 0.000067, EUR: 0.000057, GBP: 0.000049, JPY: 0.0073, CNY: 0.00043 },
    EUR: { USD: 1.18, IDR: 17500, GBP: 0.86, JPY: 130, CNY: 7.6 },
    GBP: { USD: 1.37, IDR: 20500, EUR: 1.16, JPY: 151, CNY: 8.8 },
    JPY: { USD: 0.0091, IDR: 136, EUR: 0.0077, GBP: 0.0066, CNY: 0.058 },
    CNY: { USD: 0.155, IDR: 2325, EUR: 0.132, GBP: 0.113, JPY: 17.2 }
};

const unitConversions = {
    length: {
        meter: { kilometer: 0.001, centimeter: 100, millimeter: 1000, inch: 39.37, feet: 3.281, yard: 1.094 },
        kilometer: { meter: 1000, centimeter: 100000, millimeter: 1000000, inch: 39370, feet: 3281, yard: 1094 },
        centimeter: { meter: 0.01, kilometer: 0.00001, millimeter: 10, inch: 0.394, feet: 0.0328, yard: 0.0109 },
        millimeter: { meter: 0.001, kilometer: 0.000001, centimeter: 0.1, inch: 0.0394, feet: 0.00328, yard: 0.00109 },
        inch: { meter: 0.0254, kilometer: 0.0000254, centimeter: 2.54, millimeter: 25.4, feet: 0.0833, yard: 0.0278 },
        feet: { meter: 0.305, kilometer: 0.000305, centimeter: 30.5, millimeter: 305, inch: 12, yard: 0.333 },
        yard: { meter: 0.914, kilometer: 0.000914, centimeter: 91.4, millimeter: 914, inch: 36, feet: 3 }
    },
    weight: {
        kilogram: { gram: 1000, pound: 2.205, ounce: 35.274, ton: 0.001 },
        gram: { kilogram: 0.001, pound: 0.00220, ounce: 0.0353, ton: 0.000001 },
        pound: { kilogram: 0.454, gram: 454, ounce: 16, ton: 0.000454 },
        ounce: { kilogram: 0.0284, gram: 28.35, pound: 0.0625, ton: 0.0000284 },
        ton: { kilogram: 1000, gram: 1000000, pound: 2205, ounce: 35274 }
    },
    area: {
        'square_meter': { 'square_kilometer': 0.000001, 'square_centimeter': 10000, 'square_feet': 10.764, 'square_inch': 1550, acre: 0.000247 },
        'square_kilometer': { 'square_meter': 1000000, 'square_centimeter': 10000000000, 'square_feet': 10764000, 'square_inch': 1550000000, acre: 247.1 },
        'square_centimeter': { 'square_meter': 0.0001, 'square_kilometer': 0.0000000001, 'square_feet': 0.00108, 'square_inch': 0.155, acre: 0.0000000247 },
        'square_feet': { 'square_meter': 0.0929, 'square_kilometer': 0.0000000929, 'square_centimeter': 929, 'square_inch': 144, acre: 0.0000229 },
        'square_inch': { 'square_meter': 0.000645, 'square_kilometer': 0.000000000645, 'square_centimeter': 6.45, 'square_feet': 0.00694, acre: 0.000000159 },
        acre: { 'square_meter': 4047, 'square_kilometer': 0.00405, 'square_centimeter': 40470000, 'square_feet': 43560, 'square_inch': 6273000 }
    },
    volume: {
        liter: { milliliter: 1000, gallon: 0.264, quart: 1.057, pint: 2.113, cup: 4.227 },
        milliliter: { liter: 0.001, gallon: 0.000264, quart: 0.00106, pint: 0.00211, cup: 0.00423 },
        gallon: { liter: 3.785, milliliter: 3785, quart: 4, pint: 8, cup: 16 },
        quart: { liter: 0.946, milliliter: 946, gallon: 0.25, pint: 2, cup: 4 },
        pint: { liter: 0.473, milliliter: 473, gallon: 0.125, quart: 0.5, cup: 2 },
        cup: { liter: 0.237, milliliter: 237, gallon: 0.0625, quart: 0.25, pint: 0.5 }
    }
};

const unitLabels = {
    length: {
        meter: 'Meter (m)',
        kilometer: 'Kilometer (km)',
        centimeter: 'Sentimeter (cm)',
        millimeter: 'Milimeter (mm)',
        inch: 'Inci (in)',
        feet: 'Kaki (ft)',
        yard: 'Yard (yd)'
    },
    weight: {
        kilogram: 'Kilogram (kg)',
        gram: 'Gram (g)',
        pound: 'Pound (lb)',
        ounce: 'Ons (oz)',
        ton: 'Ton (t)'
    },
    area: {
        'square_meter': 'Meter Persegi (m²)',
        'square_kilometer': 'Kilometer Persegi (km²)',
        'square_centimeter': 'Sentimeter Persegi (cm²)',
        'square_feet': 'Kaki Persegi (ft²)',
        'square_inch': 'Inci Persegi (in²)',
        acre: 'Acre'
    },
    volume: {
        liter: 'Liter (L)',
        milliliter: 'Mililiter (mL)',
        gallon: 'Galon',
        quart: 'Quart',
        pint: 'Pint',
        cup: 'Cup'
    }
};

// Fungsi untuk menampilkan converter yang dipilih
function showConverter(type) {
    // Sembunyikan semua converter
    const sections = document.querySelectorAll('.converter-section');
    sections.forEach(section => {
        section.classList.remove('active');
    });
    
    // Hapus kelas active dari semua tab
    const tabs = document.querySelectorAll('.tab-button');
    tabs.forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Tampilkan converter yang dipilih
    document.getElementById(type).classList.add('active');
    event.target.classList.add('active');
    
    // Inisialisasi unit converter jika dipilih
    if (type === 'unit') {
        updateUnitOptions();
    }
}

// Fungsi untuk menukar mata uang
function swapCurrency() {
    const fromCurrency = document.getElementById('fromCurrency');
    const toCurrency = document.getElementById('toCurrency');
    
    const temp = fromCurrency.value;
    fromCurrency.value = toCurrency.value;
    toCurrency.value = temp;
    
    // Auto convert jika ada nilai
    if (document.getElementById('currencyAmount').value) {
        convertCurrency();
    }
}

// Fungsi konversi mata uang
function convertCurrency() {
    const amount = parseFloat(document.getElementById('currencyAmount').value);
    const fromCurrency = document.getElementById('fromCurrency').value;
    const toCurrency = document.getElementById('toCurrency').value;
    const resultDiv = document.getElementById('currencyResult');
    
    if (!amount || amount <= 0) {
        resultDiv.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Masukkan jumlah yang valid';
        resultDiv.className = 'result';
        return;
    }
    
    if (fromCurrency === toCurrency) {
        resultDiv.innerHTML = `<i class="fas fa-check-circle"></i> ${formatNumber(amount)} ${fromCurrency}`;
        resultDiv.className = 'result success';
        return;
    }
    
    // Tampilkan loading
    resultDiv.innerHTML = '<div class="loading"></div>Mengkonversi...';
    resultDiv.className = 'result';
    
    setTimeout(() => {
        let result;
        if (exchangeRates[fromCurrency] && exchangeRates[fromCurrency][toCurrency]) {
            result = amount * exchangeRates[fromCurrency][toCurrency];
        } else if (exchangeRates[toCurrency] && exchangeRates[toCurrency][fromCurrency]) {
            result = amount / exchangeRates[toCurrency][fromCurrency];
        } else {
            result = amount; // Fallback
        }
        
        resultDiv.innerHTML = `<i class="fas fa-check-circle"></i> ${formatNumber(amount)} ${fromCurrency} = ${formatNumber(result)} ${toCurrency}`;
        resultDiv.className = 'result success success-animation';
    }, 500);
}

// Update opsi unit berdasarkan kategori
function updateUnitOptions() {
    const category = document.getElementById('unitCategory').value;
    const fromUnit = document.getElementById('fromUnit');
    const toUnit = document.getElementById('toUnit');
    
    // Clear existing options
    fromUnit.innerHTML = '';
    toUnit.innerHTML = '';
    
    // Add new options
    Object.keys(unitLabels[category]).forEach(unit => {
        const option1 = document.createElement('option');
        option1.value = unit;
        option1.textContent = unitLabels[category][unit];
        fromUnit.appendChild(option1);
        
        const option2 = document.createElement('option');
        option2.value = unit;
        option2.textContent = unitLabels[category][unit];
        toUnit.appendChild(option2);
    });
    
    // Set default selections
    if (fromUnit.options.length > 0) {
        fromUnit.selectedIndex = 0;
        toUnit.selectedIndex = Math.min(1, toUnit.options.length - 1);
    }
}

// Fungsi untuk menukar unit
function swapUnit() {
    const fromUnit = document.getElementById('fromUnit');
    const toUnit = document.getElementById('toUnit');
    
    const temp = fromUnit.value;
    fromUnit.value = toUnit.value;
    toUnit.value = temp;
    
    // Auto convert jika ada nilai
    if (document.getElementById('unitAmount').value) {
        convertUnit();
    }
}

// Fungsi konversi unit
function convertUnit() {
    const amount = parseFloat(document.getElementById('unitAmount').value);
    const category = document.getElementById('unitCategory').value;
    const fromUnit = document.getElementById('fromUnit').value;
    const toUnit = document.getElementById('toUnit').value;
    const resultDiv = document.getElementById('unitResult');
    
    if (!amount || amount < 0) {
        resultDiv.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Masukkan jumlah yang valid';
        resultDiv.className = 'result';
        return;
    }
    
    if (fromUnit === toUnit) {
        resultDiv.innerHTML = `<i class="fas fa-check-circle"></i> ${formatNumber(amount)} ${unitLabels[category][fromUnit]}`;
        resultDiv.className = 'result success';
        return;
    }
    
    // Tampilkan loading
    resultDiv.innerHTML = '<div class="loading"></div>Mengkonversi...';
    resultDiv.className = 'result';
    
    setTimeout(() => {
        let result;
        if (unitConversions[category][fromUnit] && unitConversions[category][fromUnit][toUnit]) {
            result = amount * unitConversions[category][fromUnit][toUnit];
        } else {
            result = amount; // Fallback
        }
        
        const fromLabel = unitLabels[category][fromUnit];
        const toLabel = unitLabels[category][toUnit];
        
        resultDiv.innerHTML = `<i class="fas fa-check-circle"></i> ${formatNumber(amount)} ${fromLabel} = ${formatNumber(result)} ${toLabel}`;
        resultDiv.className = 'result success success-animation';
    }, 300);
}

// Fungsi untuk menukar suhu
function swapTemp() {
    const fromTemp = document.getElementById('fromTemp');
    const toTemp = document.getElementById('toTemp');
    
    const temp = fromTemp.value;
    fromTemp.value = toTemp.value;
    toTemp.value = temp;
    
    // Auto convert jika ada nilai
    if (document.getElementById('tempAmount').value) {
        convertTemperature();
    }
}

// Fungsi konversi suhu
function convertTemperature() {
    const amount = parseFloat(document.getElementById('tempAmount').value);
    const fromTemp = document.getElementById('fromTemp').value;
    const toTemp = document.getElementById('toTemp').value;
    const resultDiv = document.getElementById('tempResult');
    
    if (isNaN(amount)) {
        resultDiv.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Masukkan suhu yang valid';
        resultDiv.className = 'result';
        return;
    }
    
    if (fromTemp === toTemp) {
        const symbol = getTemperatureSymbol(fromTemp);
        resultDiv.innerHTML = `<i class="fas fa-check-circle"></i> ${formatNumber(amount)}${symbol}`;
        resultDiv.className = 'result success';
        return;
    }
    
    // Tampilkan loading
    resultDiv.innerHTML = '<div class="loading"></div>Mengkonversi...';
    resultDiv.className = 'result';
    
    setTimeout(() => {
        let result = convertTemperatureValue(amount, fromTemp, toTemp);
        
        const fromSymbol = getTemperatureSymbol(fromTemp);
        const toSymbol = getTemperatureSymbol(toTemp);
        
        resultDiv.innerHTML = `<i class="fas fa-check-circle"></i> ${formatNumber(amount)}${fromSymbol} = ${formatNumber(result)}${toSymbol}`;
        resultDiv.className = 'result success success-animation';
    }, 300);
}

// Helper function untuk konversi suhu
function convertTemperatureValue(value, from, to) {
    // Convert to Celsius first
    let celsius = value;
    if (from === 'fahrenheit') {
        celsius = (value - 32) * 5/9;
    } else if (from === 'kelvin') {
        celsius = value - 273.15;
    }
    
    // Convert from Celsius to target
    if (to === 'celsius') {
        return celsius;
    } else if (to === 'fahrenheit') {
        return celsius * 9/5 + 32;
    } else if (to === 'kelvin') {
        return celsius + 273.15;
    }
    
    return celsius;
}

// Helper function untuk simbol suhu
function getTemperatureSymbol(temp) {
    switch(temp) {
        case 'celsius': return '°C';
        case 'fahrenheit': return '°F';
        case 'kelvin': return 'K';
        default: return '';
    }
}

// Fungsi konversi teks
function convertText(type) {
    const textInput = document.getElementById('textInput').value;
    const resultDiv = document.getElementById('textResult');
    
    if (!textInput.trim()) {
        resultDiv.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Masukkan teks yang ingin dikonversi';
        resultDiv.className = 'result';
        return;
    }
    
    let result = '';
    
    switch(type) {
        case 'uppercase':
            result = textInput.toUpperCase();
            break;
        case 'lowercase':
            result = textInput.toLowerCase();
            break;
        case 'capitalize':
            result = textInput.split(' ').map(word => 
                word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()
            ).join(' ');
            break;
        case 'reverse':
            result = textInput.split('').reverse().join('');
            break;
        default:
            result = textInput;
    }
    
    resultDiv.innerHTML = `<div style="word-break: break-all;">${result}</div>`;
    resultDiv.className = 'result success success-animation';
    
    // Add copy button
    setTimeout(() => {
        const copyButton = document.createElement('button');
        copyButton.innerHTML = '<i class="fas fa-copy"></i> Salin';
        copyButton.style.marginTop = '10px';
        copyButton.style.padding = '5px 15px';
        copyButton.style.background = '#667eea';
        copyButton.style.color = 'white';
        copyButton.style.border = 'none';
        copyButton.style.borderRadius = '5px';
        copyButton.style.cursor = 'pointer';
        copyButton.onclick = () => copyToClipboard(result);
        
        resultDiv.appendChild(copyButton);
    }, 100);
}

// Fungsi untuk copy ke clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        // Show success message
        const toast = document.createElement('div');
        toast.innerHTML = '<i class="fas fa-check"></i> Teks berhasil disalin!';
        toast.style.position = 'fixed';
        toast.style.top = '20px';
        toast.style.right = '20px';
        toast.style.background = '#28a745';
        toast.style.color = 'white';
        toast.style.padding = '10px 20px';
        toast.style.borderRadius = '5px';
        toast.style.zIndex = '1000';
        toast.style.animation = 'fadeIn 0.3s ease-in';
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            document.body.removeChild(toast);
        }, 2000);
    });
}

// Helper function untuk format angka
function formatNumber(num) {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(2) + 'M';
    } else if (num >= 1000) {
        return (num / 1000).toFixed(2) + 'K';
    } else if (num < 0.01 && num > 0) {
        return num.toExponential(4);
    } else {
        return num.toFixed(2).replace(/\.?0+$/, '');
    }
}

// Event listeners untuk auto-convert
document.addEventListener('DOMContentLoaded', function() {
    // Initialize unit converter
    updateUnitOptions();
    
    // Auto convert on input change
    document.getElementById('currencyAmount').addEventListener('input', convertCurrency);
    document.getElementById('fromCurrency').addEventListener('change', convertCurrency);
    document.getElementById('toCurrency').addEventListener('change', convertCurrency);
    
    document.getElementById('unitAmount').addEventListener('input', convertUnit);
    document.getElementById('fromUnit').addEventListener('change', convertUnit);
    document.getElementById('toUnit').addEventListener('change', convertUnit);
    
    document.getElementById('tempAmount').addEventListener('input', convertTemperature);
    document.getElementById('fromTemp').addEventListener('change', convertTemperature);
    document.getElementById('toTemp').addEventListener('change', convertTemperature);
    
    // Initial conversions
    convertCurrency();
    convertUnit();
    convertTemperature();
});