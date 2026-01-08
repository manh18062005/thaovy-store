function register() {
    let name = document.getElementById("regName").value.trim();
    let email = document.getElementById("regEmail").value.trim();
    let password = document.getElementById("regPassword").value.trim();
    let msg = document.getElementById("msg");

    // Basic validations
    if (name.length < 2) {
        msg.textContent = "Họ tên phải có ít nhất 2 kí tự.";
        return;
    }

    if (email === "") {
        msg.textContent = "Vui lòng nhập email.";
        return;
    }

    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRe.test(email)) {
        msg.textContent = "Email không đúng định dạng (ví dụ: user@example.com).";
        return;
    }

    if (password.length < 6) {
        msg.textContent = "Mật khẩu phải có ít nhất 6 kí tự.";
        return;
    }

    let users = JSON.parse(localStorage.getItem("users")) || [];

    const emailLower = email.toLowerCase();
    if (users.some(u => (u.email || '').toLowerCase() === emailLower)) {
        msg.textContent = "Email đã tồn tại!";
        return;
    }

    users.push({ name, email: emailLower, password });
    localStorage.setItem("users", JSON.stringify(users));
    msg.textContent = "Đăng ký thành công! Chuyển hướng...";
    
    setTimeout(() => {
        window.location.href = "login.html";
    }, 1000);
}
