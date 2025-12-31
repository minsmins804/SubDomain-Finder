# 🕵️ Subdomain Finder Extension

-Công cụ tìm kiếm Subdomain mạnh mẽ, nhanh gọn chạy trực tiếp trên trình duyệt (Chrome/Edge/Cốc Cốc).
Dự án được chuyển đổi từ Python Script sang Web Extension để tiện lợi hơn trong quá trình Reconnaissance.

-GVHD: Thầy Trần Tuấn Dũng

## 🚀 Tính năng nổi bật

* **Tốc độ cao:** Sử dụng cơ chế tìm kiếm thụ động (Passive Enumeration) từ 3 nguồn uy tín:

  * HackerTarget
  * Crt.sh (Certificate Transparency)
  * AlienVault OTX

* **Không cần API Key:** Cài đặt là chạy ngay, không cần cấu hình phức tạp.
* **Check Cloud Provider:** Tự động kiểm tra HTTP Header để phát hiện nếu subdomain đang sử dụng **Cloudflare** hoặc **AWS**.
* **Tự động lưu (Auto-save):** Kết quả quét được lưu lại trong bộ nhớ trình duyệt, không bị mất đi khi tắt Popup.
* **Tiện ích:**

  * Click vào subdomain để mở tab mới.
  * Nút **Copy All** để sao chép toàn bộ danh sách.
  * Nút **Xóa** để dọn dẹp kết quả cũ.

  ⚙️ Hướng dẫn cài đặt (Installation)
  

  Vì đây là Extension dạng Developer (Unpacked), bạn cần cài đặt thủ công theo 3 bước sau:

  

  

  **Bước 1**: Chuẩn bị
  	Tải source code về máy và giải nén. Đảm bảo bạn đã thấy thư mục tên là MySubdomainTool chứa 4 file code trên.

  

  

  **Bước 2**: Mở trình quản lý Extension
  	Mở trình duyệt (Chrome, Edge, Brave, hoặc Cốc Cốc).

  &nbsp;	Nhập địa chỉ sau vào thanh URL và nhấn Enter:

  &nbsp;	Chrome: chrome://extensions/

  &nbsp;	Edge: edge://extensions/

  &nbsp;	QUAN TRỌNG: Bật chế độ Developer mode (Chế độ dành cho nhà phát triển) ở góc trên bên phải màn hình.

  

  

  **Bước 3**: Tải Extension lên
  	Nhấn vào nút Load unpacked (Tải tiện ích đã giải nén) ở góc trái trên cùng.

  &nbsp;	Một cửa sổ chọn thư mục hiện ra.

  &nbsp;	Lưu ý: Hãy chọn đúng thư mục MySubdomainTool (thư mục con chứa file manifest.json).

  &nbsp;	Nhấn Select Folder.

  🎉 Biểu tượng Extension sẽ xuất hiện trên thanh công cụ của trình duyệt.

  

  

  📖 **Cách sử dụng**
  
  -Click vào icon Subdomain Finder trên thanh trình duyệt (Ghim nó ra ngoài để dễ bấm).

  -Nhập tên miền cần quét vào ô trống (Ví dụ: uit.edu.vn, google.com).

  -Nhấn Enter hoặc nút Quét.

  -Đợi vài giây để tool thu thập dữ liệu.

  -Kết quả sẽ hiển thị danh sách Subdomain và trạng thái Server (Cloudflare/AWS/Online).

  

  

  ⚠️ **Lưu ý**
  Tool sử dụng các nguồn Passive nên rất an toàn, không gửi gói tin tấn công trực tiếp vào mục tiêu.

  Cột trạng thái "Server/Cloud" có thể hiện thị "Unreachable" hoặc "Online" nếu server chặn request check header (CORS policy), nhưng subdomain đó vẫn tồn tại.

  

  

  🤝 **Đóng góp**
  Mọi đóng góp, báo lỗi hoặc yêu cầu tính năng mới đều được hoan nghênh. Hãy tạo Pull Request hoặc Issue trên GitHub.

  

  Developed by Team 14 

