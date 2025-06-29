const fs = require('fs');
const path = require('path');

function loadJson(filePath) {
  try {
    const data = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error(`Failed to load: ${filePath} (${err.message})`);
    return [];
  }
}

const regions   = loadJson(path.join(__dirname, 'ph-json', 'region.json'));
const provinces = loadJson(path.join(__dirname, 'ph-json', 'province.json'));
const cities    = loadJson(path.join(__dirname, 'ph-json', 'city.json'));
const barangays = loadJson(path.join(__dirname, 'ph-json', 'barangay.json'));

const output = [];

regions.forEach(region => {
  const provs = provinces.filter(p => p.region_code === region.region_code);
  provs.forEach(province => {
    const cits = cities.filter(c => c.province_code === province.province_code);
    cits.forEach(city => {
      const brgys = barangays.filter(b => b.city_code === city.city_code);
      brgys.forEach(barangay => {
        output.push({
          region: region.region_name || region.name,
          province: province.province_name || province.name,
          city: city.city_name || city.name,
          barangay: barangay.brgy_name || barangay.name,
          postal_code: city.postal_code || '',
        });
      });
    });
  });
});

const staticDir = path.join(__dirname, 'static');
if (!fs.existsSync(staticDir)) {
  fs.mkdirSync(staticDir);
}

const outPath = path.join(staticDir, 'addressData.json');
fs.writeFileSync(outPath, JSON.stringify(output, null, 2), 'utf8');
console.log(`addressData.json generated! (${output.length} addresses)`);