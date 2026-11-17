# NetGuard

**NetGuard** là hệ thống giám sát an ninh và quản lý sự kiện tập trung.

Hệ thống tách biệt rõ ràng giữa tầng thu thập dữ liệu viết bằng **C++** đặt tại các máy mục tiêu (*Agent*) và tầng xử lý, lưu trữ, cảnh báo tập trung (*Server*) viết bằng **Python (FastAPI)** và gửi thông báo qua **Telegram Bot**.

---

## Kiến trúc & Luồng hoạt động

NetGuard vận hành theo mô hình **Client – Server một chiều**. Các máy chạy Agent chủ động đẩy dữ liệu cảnh báo về Server trung tâm thông qua giao thức `HTTP POST`.

```text
[ Target Linux Host ]                                  [ Central SIEM Server ]
┌────────────────────────────┐                        ┌──────────────────────────────────────┐
│  systemd / journalctl      │                        │  FastAPI Endpoint (/api/alerts)      │
│         │ (real-time log)  │                        │   ├─ Xác thực Header (X-API)         │
│         ▼                  │   HTTP POST (JSON)     │   ├─ Lưu đồng bộ ──► SQLite (.db)    │
│  NetGuard C++ Agent        │ ─────────────────────► │   └─ BackgroundTasks                 │
│   ├─ Lọc mẫu hành vi       │  (siem.netguard.local) │       └─ httpx (async) ──► Telegram   │
│   ├─ Leaky Bucket          │                        └──────────────────────────────────────┘
│   └─ Ghi backup (.jsonl)   │
└────────────────────────────┘
```

### 1. Tầng thu thập (C++ Agent)

* **Giám sát thời gian thực:** Đọc trực tiếp luồng nhật ký hệ thống từ `journalctl`.
* **Dự phòng cục bộ:** Mọi cảnh báo trước khi gửi đi đều được ghi song song ra tệp `alerts.jsonl` trên máy để đảm bảo không mất *log* ngay cả khi đường truyền tới Server gặp sự cố.

### 2. Tầng xử lý & Cảnh báo (FastAPI Server)

* **Xác thực tầng ứng dụng:** Mọi gói tin gửi tới endpoint `/api/alerts` đều phải đi qua lớp kiểm tra khóa bí mật tại header `X-API` trước khi được phân tích cú pháp (*Payload Validation*).
* **Lưu trữ không phụ thuộc (Zero-Dependency Persistence):** Sử dụng **SQLite** tích hợp sẵn để lưu trữ toàn bộ lịch sử sự kiện. Người dùng có thể triển khai hệ thống ngay lập tức mà không cần cài đặt thêm các hệ quản trị cơ sở dữ liệu.
* **Thông báo bất đồng bộ (BackgroundTasks):** Sau khi ghi nhận bản ghi vào SQLite, Server lập tức phản hồi `200 OK` để giải phóng kết nối cho Agent. Tác vụ gọi API Telegram được đẩy sang luồng nền thông qua `httpx.AsyncClient` với giới hạn chờ (`timeout=5.0`), đảm bảo độ trễ mạng bên ngoài không bao giờ làm nghẽn hệ thống.

---

## Nguyên tắc Bảo mật & Vận hành

* **Tách biệt cấu hình nhạy cảm:** Toàn bộ khóa API (`NETGUARD_API_KEY`), Token và Chat ID của Telegram được quản lý qua biến môi trường (`.env`) và loại trừ khỏi mã nguồn.
* **Tối thiểu hóa dữ liệu:** Do Telegram Bot API không mã hóa đầu cuối, tin nhắn cảnh báo đẩy ra ngoài chỉ chứa Mã sự kiện (`#ID`), Mức độ nghiêm trọng, Loại tấn công và Thời gian. Toàn bộ nội dung log thô chi tiết (`detail`) được giữ an toàn bên trong cơ sở dữ liệu nội bộ của Server.
* **Định danh qua tên miền nội bộ:** Hỗ trợ cấu hình URL động thông qua biến môi trường `NETGUARD_SERVER_URL`.

---

## Cấu trúc thư mục

```text
netguard/
├── agent/
│   ├── main.cpp            # Luồng chính và giám sát port
│   ├── .env.txt            # Mẫu khai báo biến môi trường
    ├── auth_test.cpp       # Giám sát journal và gửi cảnh báo
│   └── alerts.jsonl        # File backup cục bộ (được tạo khi Agent chạy)
├── server/
│   ├── main.py             # FastAPI Server xử lý API, SQLite và Telegram Bot
│   ├── .env.txt        # Mẫu khai báo biến môi trường
│   └── requirements.txt    # Danh sách thư viện Python cần thiết
└── README.md
```

---

## Hướng dẫn Cài đặt & Triển khai

### 1. Khởi chạy Central Server

Cài đặt các thư viện phụ thuộc.

```bash
cd server
pip install -r requirements.txt
```

###### Cập nhật thông tin cấu hình trong tệp `.env`.

***Chỉ sử dụng khi demo trên local***

### 2. Khởi chạy Server:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

### 3. Biên dịch & Chạy C++ Agent

```bash
chmod +x run_agent.sh
./run_agent.sh
```
---

## Kiểm thử mô phỏng tấn công

Để kiểm tra toàn tuyến luồng dữ liệu từ **Agent → FastAPI → SQLite → Telegram**, mở một terminal khác trên máy chạy Agent và giả lập chuỗi đăng nhập SSH thất bại liên tiếp bằng tiện ích `logger`:

```bash
for i in {1..5}; do
  logger "Failed password for root from 10.0.0.99 port 22 ssh2"
done
```

Ngay khi vượt ngưỡng kích hoạt, Agent sẽ đóng gói cảnh báo `BRUTE_FORCE` gửi về Server, lưu bản ghi vào `server/netguard.db` và bắn thông báo tức thì về Telegram.

Các alert port mới có event type `NEW_PORT_DETECTED` và chứa địa chỉ đang
listen trong trường `detail`. Agent chỉ phát cảnh báo một lần cho mỗi port
cho đến khi port biến mất rồi xuất hiện lại.

---

## Định hướng phát triển

Hệ thống đang tiếp tục được mở rộng thêm các lớp giám sát trực tiếp từ nhân Linux mà không cần thay đổi cấu trúc Backend:

* **Giám sát leo thang đặc quyền (`PRIV_ESC`):** Phát hiện hành vi lạm dụng `sudo` hoặc gọi shell root trái phép qua `journalctl`.
* **Giám sát mạng (Network Telemetry):** Đọc trực tiếp `/proc/net/tcp` để phát hiện các cổng `LISTEN` lạ mở trái phép hoặc kết nối Reverse Shell đi ra ngoài.
