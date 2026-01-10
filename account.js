document.addEventListener("DOMContentLoaded", () => {
    // load user from localStorage
    let user = null;
    try {
        user = JSON.parse(localStorage.getItem('loggedUser')) || JSON.parse(localStorage.getItem('loggedInUser'));
    } catch (e) { user = null; }

    // Nếu chưa login thì đưa về trang đăng nhập
    if (!user) {
        alert('Bạn cần đăng nhập!');
        location.href = 'login.html';
        return;
    }

    // helper to persist to both keys used in project
    function persistUser(u) {
        localStorage.setItem('loggedUser', JSON.stringify(u));
        localStorage.setItem('loggedInUser', JSON.stringify(u));
        // Also update the central `users` array if the user exists there, so changes persist after re-login
        try {
            const users = JSON.parse(localStorage.getItem('users')) || [];
            if (u && u.email) {
                const targetEmail = u.email.toString().trim().toLowerCase();
                const idx = users.findIndex(x => (x.email || '').toString().trim().toLowerCase() === targetEmail);
                if (idx >= 0) {
                    users[idx] = Object.assign({}, users[idx], u);
                } else {
                    // if not found, add to users
                    users.push(u);
                }
                localStorage.setItem('users', JSON.stringify(users));
            }
        } catch (e) {
            // ignore
        }
    }

    // Đồng bộ dữ liệu từ LocalStorage lên trang
    document.getElementById('fullName').value = user.fullName || user.name || '';
    document.getElementById('email').value = user.email || '';
    document.getElementById('gender').value = user.gender || 'Nam';
    document.getElementById('birthday').value = user.birthday || '';
    document.getElementById('displayName').innerText = user.fullName || user.name || 'User';

    // Bank
    const bankNameEl = document.getElementById('bankName');
    if (user.bankNumber) document.getElementById('bankNumber').value = user.bankNumber;

    // Populate Vietnamese banks list
    const vnBanks = [
        'Vietcombank', 'VietinBank', 'BIDV', 'Techcombank', 'VPBank', 'MB Bank', 'ACB', 'Sacombank',
        'HSBC VN', 'TPBank', 'VIB', 'SCB', 'Eximbank', 'HDBank', 'SHB', 'SeABank', 'OCB', 'MSB',
        'PVcomBank', 'Bac A Bank', 'LienVietPostBank', 'Agribank', 'OceanBank', 'ABBANK'
    ];

    if (bankNameEl) {
        // fill options
        vnBanks.forEach(b => {
            const opt = document.createElement('option'); opt.value = b; opt.textContent = b; bankNameEl.appendChild(opt);
        });
        // set current value if exists
        if (user.bankName) bankNameEl.value = user.bankName;
    }

    // Avatar
    if (user.avatar) document.getElementById('avatarPreview').src = user.avatar;

    // Address structure: will be loaded from vn-address.json (province -> district -> ward)
    const cityEl = document.getElementById('city');
    const districtEl = document.getElementById('district');
    const wardEl = document.getElementById('ward');
    const detailEl = document.getElementById('addressDetail');

    let citiesData = null;

    function populateCitiesFromData() {
        cityEl.innerHTML = '<option value="">Chọn tỉnh/thành</option>';
        Object.keys(citiesData).forEach(c => {
            const opt = document.createElement('option'); opt.value = c; opt.textContent = c; cityEl.appendChild(opt);
        });
    }

    function populateDistrictsFromData(city) {
        districtEl.innerHTML = '<option value="">Chọn quận/huyện</option>';
        wardEl.innerHTML = '<option value="">Chọn phường/xã</option>';
        if (!city || !citiesData || !citiesData[city]) return;
        Object.keys(citiesData[city]).forEach(d => {
            const opt = document.createElement('option'); opt.value = d; opt.textContent = d; districtEl.appendChild(opt);
        });
    }

    function populateWardsFromData(city, district) {
        wardEl.innerHTML = '<option value="">Chọn phường/xã</option>';
        if (!city || !district || !citiesData || !citiesData[city] || !citiesData[city][district]) return;
        citiesData[city][district].forEach(w => {
            const opt = document.createElement('option'); opt.value = w; opt.textContent = w; wardEl.appendChild(opt);
        });
    }

    // Try to load vn-address.json; fallback to a minimal built-in set if fetch fails
    fetch('vn-address.json').then(r => {
        if (!r.ok) throw new Error('Network');
        return r.json();
    }).then(json => {
        citiesData = json;
        populateCitiesFromData();

        // If user already has address, preselect
        if (user.address && typeof user.address === 'object') {
            if (user.address.city) cityEl.value = user.address.city;
            populateDistrictsFromData(user.address.city);
            if (user.address.district) districtEl.value = user.address.district;
            populateWardsFromData(user.address.city, user.address.district);
            if (user.address.ward) wardEl.value = user.address.ward;
            if (user.address.detail) detailEl.value = user.address.detail;
        }
    }).catch(() => {
        // fallback minimal data
        citiesData = {
            'Đà Nẵng': { 'Hải Châu': ['Thuận Phước','Thạch Thang'], 'Sơn Trà': ['An Hải Bắc','An Hải Đông'] },
            'Hà Nội': { 'Ba Đình': ['Phúc Xá','Trúc Bạch'], 'Hoàn Kiếm': ['Hàng Trống'] },
            'Hồ Chí Minh': { 'Quận 1': ['Bến Nghé','Bến Thành'] }
        };
        populateCitiesFromData();
        // preselect fallback if user.address exists
        if (user.address && typeof user.address === 'object') {
            if (user.address.city) cityEl.value = user.address.city;
            populateDistrictsFromData(user.address.city);
            if (user.address.district) districtEl.value = user.address.district;
            populateWardsFromData(user.address.city, user.address.district);
            if (user.address.ward) wardEl.value = user.address.ward;
            if (user.address.detail) detailEl.value = user.address.detail;
        }
    });

    cityEl.addEventListener('change', () => {
        populateDistrictsFromData(cityEl.value);
    });

    districtEl.addEventListener('change', () => {
        populateWardsFromData(cityEl.value, districtEl.value);
    });

    // --- Auto-save listeners (debounced) ---
    function debounce(fn, wait = 400) {
        let t;
        return function (...args) {
            clearTimeout(t);
            t = setTimeout(() => fn.apply(this, args), wait);
        };
    }

    const saveProfileDebounced = debounce(() => {
        user.fullName = document.getElementById('fullName').value.trim();
        user.gender = document.getElementById('gender').value;
        user.birthday = document.getElementById('birthday').value;
        persistUser(user);
        document.getElementById('displayName').innerText = user.fullName || user.name || 'User';
    }, 500);

    document.getElementById('fullName').addEventListener('input', saveProfileDebounced);
    document.getElementById('gender').addEventListener('change', saveProfileDebounced);
    document.getElementById('birthday').addEventListener('change', saveProfileDebounced);

    // Bank auto-save
    const saveBankDebounced = debounce(() => {
        user.bankName = (bankNameEl && bankNameEl.value) ? bankNameEl.value.trim() : '';
        user.bankNumber = document.getElementById('bankNumber').value.trim();
        persistUser(user);
    }, 500);
    if (bankNameEl) bankNameEl.addEventListener('change', saveBankDebounced);
    document.getElementById('bankNumber').addEventListener('input', saveBankDebounced);
    document.getElementById('bankNumber').addEventListener('input', saveBankDebounced);

    // Address selects auto-save
    cityEl.addEventListener('change', () => {
        populateDistrictsFromData(cityEl.value);
        user.address = user.address || {};
        user.address.city = cityEl.value || '';
        // reset dependent fields
        user.address.district = '';
        user.address.ward = '';
        persistUser(user);
    });

    districtEl.addEventListener('change', () => {
        populateWardsFromData(cityEl.value, districtEl.value);
        user.address = user.address || {};
        user.address.district = districtEl.value || '';
        user.address.ward = '';
        persistUser(user);
    });

    wardEl.addEventListener('change', () => {
        user.address = user.address || {};
        user.address.ward = wardEl.value || '';
        persistUser(user);
    });

    detailEl.addEventListener('input', debounce(() => {
        user.address = user.address || {};
        user.address.detail = detailEl.value.trim() || '';
        persistUser(user);
    }, 500));

    // Chuyển tab
    document.querySelectorAll('.account-menu li').forEach(li => {
        li.addEventListener('click', () => {
            document.querySelectorAll('.account-menu li').forEach(i => i.classList.remove('active'));
            li.classList.add('active');

            document.querySelectorAll('.content-box').forEach(box => box.classList.add('hidden'));
            document.getElementById(li.dataset.section).classList.remove('hidden');
        });
    });

    // Lưu hồ sơ
    document.getElementById('saveProfile').onclick = () => {
        user.fullName = document.getElementById('fullName').value;
        user.gender = document.getElementById('gender').value;
        user.birthday = document.getElementById('birthday').value;
        persistUser(user);
        document.getElementById('displayName').innerText = user.fullName;
        alert('Đã lưu hồ sơ!');
    };

    // Lưu thông tin ngân hàng
    document.getElementById('saveBank').onclick = () => {
        user.bankName = document.getElementById('bankName').value.trim();
        user.bankNumber = document.getElementById('bankNumber').value.trim();
        persistUser(user);
        alert('Đã lưu ngân hàng!');
    };

    // Lưu địa chỉ
    document.getElementById('saveAddress').onclick = () => {
        user.address = {
            city: cityEl.value || '',
            district: districtEl.value || '',
            ward: wardEl.value || '',
            detail: detailEl.value.trim() || ''
        };
        persistUser(user);
        alert('Đã lưu địa chỉ!');
    };

    // Đổi mật khẩu
    document.getElementById('changePass').onclick = () => {
        const oldPass = document.getElementById('oldPass').value;
        const newPass = document.getElementById('newPass').value;
        if (!user.password) {
            alert('Không có mật khẩu gốc để kiểm tra.');
            return;
        }
        if (oldPass !== user.password) return alert('Sai mật khẩu!');
        if (newPass.length < 6) return alert('Mật khẩu phải ≥ 6 ký tự!');
        user.password = newPass;
        persistUser(user);
        alert('Đổi mật khẩu thành công!');
        document.getElementById('oldPass').value = '';
        document.getElementById('newPass').value = '';
    };

    // Upload avatar
    document.getElementById('avatarUpload').addEventListener('change', (e) => {
        const file = e.target.files && e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
            document.getElementById('avatarPreview').src = reader.result;
            user.avatar = reader.result;
            persistUser(user);
        };
        reader.readAsDataURL(file);
    });

    // Mặc định mở tab Hồ sơ
    const defaultTab = document.querySelector('.account-menu li[data-section="profileSection"]');
    if (defaultTab) defaultTab.click();

    // Logout button
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            // clear session keys but keep `users` data
            localStorage.removeItem('loggedUser');
            localStorage.removeItem('loggedInUser');
            // optionally remove other session-like keys
            try { localStorage.removeItem('sessionToken'); } catch (e) {}
            alert('Bạn đã đăng xuất.');
            location.href = 'index.html';
        });
    }
});
