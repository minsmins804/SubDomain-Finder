document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scanBtn');
    const copyBtn = document.getElementById('copyBtn');
    const clearBtn = document.getElementById('clearBtn');
    const domainInput = document.getElementById('domainInput');
    const status = document.getElementById('status');
    const tbody = document.querySelector('#resultTable tbody');

    // 1. KHI MỞ EXTENSION: TỰ ĐỘNG LẤY DỮ LIỆU CŨ RA
    chrome.storage.local.get(['savedResults', 'savedDomain'], (result) => {
        if (result.savedResults && result.savedResults.length > 0) {
            domainInput.value = result.savedDomain || "";
            renderTable(result.savedResults, false); // false = không check lại cloud ngay để đỡ lag
            status.innerText = `Đã khôi phục ${result.savedResults.length} kết quả cũ.`;
            copyBtn.disabled = false;
            clearBtn.style.display = 'block';
        }
    });

    // 2. NÚT QUÉT
    scanBtn.addEventListener('click', startScan);

    // 3. NÚT COPY
    copyBtn.addEventListener('click', async () => {
        const links = tbody.querySelectorAll('tr td:first-child a');
        if (links.length === 0) return;
        const textToCopy = Array.from(links).map(link => link.innerText).join('\n');
        await navigator.clipboard.writeText(textToCopy);
        const originalText = copyBtn.innerText;
        copyBtn.innerText = "✅ Đã Copy!";
        setTimeout(() => { copyBtn.innerText = originalText; }, 2000);
    });

    // 4. NÚT XÓA (MỚI)
    clearBtn.addEventListener('click', () => {
        chrome.storage.local.remove(['savedResults', 'savedDomain']); // Xóa trong kho
        tbody.innerHTML = ''; // Xóa giao diện
        domainInput.value = '';
        status.innerText = "Sẵn sàng";
        copyBtn.disabled = true;
        clearBtn.style.display = 'none';
    });

    domainInput.addEventListener('keypress', (e) => {
        if(e.key === 'Enter') scanBtn.click();
    });

    async function startScan() {
        const domain = domainInput.value.trim();
        if (!domain) { alert("Vui lòng nhập tên miền!"); return; }

        scanBtn.disabled = true;
        copyBtn.disabled = true;
        clearBtn.style.display = 'none';
        scanBtn.innerText = "⏳...";
        tbody.innerHTML = '';
        status.innerText = `Đang kết nối...`;

        // Xóa dữ liệu cũ trước khi scan mới
        chrome.storage.local.remove(['savedResults', 'savedDomain']);

        try {
            const [hackertarget, crtsh, otx] = await Promise.all([
                fetchHackerTarget(domain),
                fetchCrtSh(domain),
                fetchOtx(domain)
            ]);

            const allSubs = new Set([...hackertarget, ...crtsh, ...otx]);
            const finalSubs = Array.from(allSubs)
                .filter(s => s.includes('.') && !s.startsWith('.'))
                .sort();

            if (finalSubs.length === 0) {
                status.innerText = "Không tìm thấy kết quả nào.";
                resetButtons();
                return;
            }

            // LƯU VÀO KHO (STORAGE)
            chrome.storage.local.set({ 
                savedResults: finalSubs,
                savedDomain: domain
            });

            // Hiển thị ra bảng
            renderTable(finalSubs, true); // true = check cloud ngay

            status.innerText = `Tìm thấy ${finalSubs.length} kết quả.`;
            copyBtn.disabled = false;
            clearBtn.style.display = 'block';

        } catch (error) {
            console.error(error);
            status.innerText = "Lỗi: " + error.message;
        } finally {
            resetButtons();
        }
    }

    // Hàm hiển thị bảng (Tách ra để dùng lại lúc khôi phục)
    function renderTable(subdomains, checkCloudNow) {
        tbody.innerHTML = ''; // Reset bảng cũ nếu có
        for (const sub of subdomains) {
            const row = tbody.insertRow();
            const cellName = row.insertCell(0);
            const cellCloud = row.insertCell(1);
            cellCloud.className = "status-cell";

            const link = document.createElement('a');
            link.href = `http://${sub}`;
            link.target = '_blank';
            link.innerText = sub;
            cellName.appendChild(link);

            if (checkCloudNow) {
                cellCloud.innerText = "⏳";
                detectCloud(sub, cellCloud);
            } else {
                // Nếu là khôi phục từ storage thì chưa check vội cho đỡ lag
                cellCloud.innerText = "-"; 
                // Nếu muốn check lại khi khôi phục, bỏ comment dòng dưới:
                detectCloud(sub, cellCloud); 
            }
        }
    }

    function resetButtons() {
        scanBtn.disabled = false;
        scanBtn.innerText = "Quét";
    }
});

// --- CÁC HÀM API & DETECT CLOUD GIỮ NGUYÊN ---
async function fetchHackerTarget(domain) {
    try {
        const res = await fetch(`https://api.hackertarget.com/hostsearch/?q=${domain}`);
        const text = await res.text();
        if(text.includes('error')) return [];
        return text.split('\n').map(l => l.split(',')[0]).filter(l => l.endsWith(domain));
    } catch { return []; }
}
async function fetchCrtSh(domain) {
    try {
        const res = await fetch(`https://crt.sh/?q=%.${domain}&output=json`);
        const data = await res.json();
        return data.map(i => i.name_value.toLowerCase()).filter(n => !n.includes('*') && n.endsWith(domain));
    } catch { return []; }
}
async function fetchOtx(domain) {
    try {
        const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`);
        const data = await res.json();
        return data.passive_dns.map(i => i.hostname.toLowerCase()).filter(h => h.endsWith(domain));
    } catch { return []; }
}

async function detectCloud(subdomain, cellElement) {
    try {
        const controller = new AbortController();
        setTimeout(() => controller.abort(), 5000);
        const res = await fetch(`http://${subdomain}`, { method: 'HEAD', signal: controller.signal, mode: 'no-cors' });
        
        const server = (res.headers.get('server') || '').toLowerCase();
        
        if (server.includes('cloudflare')) {
            cellElement.innerText = "Cloudflare"; cellElement.className = "cloudflare";
        } else if (server.includes('cloudfront') || server.includes('amazon')) {
            cellElement.innerText = "AWS"; cellElement.className = "aws";
        } else if (server) {
            cellElement.innerText = server.length > 15 ? server.substring(0, 15) + '...' : server;
        } else {
            cellElement.innerText = "Online";
        }
    } catch (e) {
        cellElement.innerText = "Unreachable";
    }
}