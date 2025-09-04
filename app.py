import os
import zipfile
import tempfile
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import uuid
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    send_from_directory,
    send_file,
    flash,
    session,
)
from werkzeug.utils import secure_filename
from urllib.parse import unquote
import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Use environment variable for secret key
app.secret_key = os.environ.get(
    "SECRET_KEY", "your-secret-key-change-this-in-production"
)

# Admin Credentials - Change these values or use environment variables
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "pcboy")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "cant_findit#@boys")

# AWS S3 Configuration from environment variables
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.environ.get("AWS_REGION", "ap-south-1")
S3_BUCKET_NAME = os.environ.get("S3_BUCKET_NAME", "fileshare-aaus1bz4")
S3_PUBLIC_URL_BASE = os.environ.get(
    "S3_PUBLIC_URL_BASE", "https://fileshare-aaus1bz4.s3.ap-south-1.amazonaws.com"
)

# Initialize S3 client
s3_client = None
try:
    if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY:
        s3_client = boto3.client(
            "s3",
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_REGION,
        )
        print("✅ S3 client initialized successfully")

        # Test S3 connection
        try:
            s3_client.head_bucket(Bucket=S3_BUCKET_NAME)
            print(f"✅ S3 bucket '{S3_BUCKET_NAME}' is accessible")
        except Exception as e:
            print(f"❌ S3 bucket access test failed: {e}")
    else:
        print("❌ AWS credentials not found in environment variables")
except Exception as e:
    print(f"❌ Could not initialize S3 client: {e}")

# Configuration
UPLOAD_FOLDER = "uploads"  # Keep for backward compatibility
ALLOWED_EXTENSIONS = {
    # Documents
    "txt",
    "pdf",
    "doc",
    "docx",
    "xlsx",
    "xls",
    "ppt",
    "pptx",
    "odt",
    "ods",
    "odp",
    "rtf",
    "csv",
    "md",
    "epub",
    "tex",
    # Images
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp",
    "svg",
    "bmp",
    "tiff",
    "tif",
    "ico",
    "psd",
    "ai",
    "eps",
    "raw",
    "cr2",
    "nef",
    "dng",
    # Audio
    "mp3",
    "wav",
    "flac",
    "aac",
    "ogg",
    "wma",
    "m4a",
    "mid",
    "midi",
    "opus",
    "ape",
    "ac3",
    "amr",
    # Video
    "mp4",
    "avi",
    "mov",
    "wmv",
    "flv",
    "webm",
    "mkv",
    "m4v",
    "3gp",
    "mpg",
    "mpeg",
    "ogv",
    "rm",
    "rmvb",
    "asf",
    "vob",
    # Programming
    "js",
    "jsx",
    "ts",
    "tsx",
    "py",
    "java",
    "cpp",
    "c",
    "cs",
    "php",
    "rb",
    "go",
    "rs",
    "html",
    "css",
    "scss",
    "sass",
    "json",
    "xml",
    "yaml",
    "yml",
    "sql",
    "sh",
    "bat",
    "vue",
    "svelte",
    "swift",
    "kt",
    "dart",
    "r",
    "scala",
    "pl",
    "lua",
    # Archives
    "zip",
    "rar",
    "7z",
    "tar",
    "gz",
    "bz2",
    "xz",
    "lzma",
    "cab",
    "iso",
    "dmg",
    "deb",
    "rpm",
    # Others
    "exe",
    "msi",
    "apk",
    "ipa",
    "app",
    "appx",
    "snap",
    "flatpak",
    "ttf",
    "otf",
    "woff",
    "woff2",
    "eot",
    "obj",
    "fbx",
    "dae",
    "3ds",
    "blend",
    "max",
    "dwg",
    "dxf",
    "step",
    "stp",
    "iges",
    "igs",
    "stl",
    "ply",
    "db",
    "sqlite",
    "mdb",
    "accdb",
    "dbf",
    "torrent",
    "magnet",
    "nfo",
}

MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 200MB max file size
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# Create upload directory if it doesn't exist (for backward compatibility)
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def allowed_file(filename):
    """Check if file extension is allowed"""
    if "." not in filename:
        return True  # Allow files without extensions
    return filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def upload_to_s3(file, filename, folder_path=""):
    """Upload file to S3 bucket"""
    if not s3_client:
        raise Exception("S3 client not initialized. Check AWS credentials.")

    try:
        # Create S3 key (path) - preserve folder structure
        s3_key = f"{folder_path}/{filename}" if folder_path else filename
        s3_key = s3_key.replace("\\", "/")  # Normalize path separators

        # Upload file to S3
        s3_client.upload_fileobj(
            file,
            S3_BUCKET_NAME,
            s3_key,
            ExtraArgs={
                "ServerSideEncryption": "AES256",
                "ContentType": file.content_type or "binary/octet-stream",
            },
        )
        return s3_key
    except ClientError as e:
        raise Exception(f"Failed to upload to S3: {e}")
    except NoCredentialsError:
        raise Exception("AWS credentials not configured")


def list_s3_objects(prefix=""):
    """List objects in S3 bucket with optional prefix"""
    if not s3_client:
        return []

    try:
        response = s3_client.list_objects_v2(Bucket=S3_BUCKET_NAME, Prefix=prefix)
        return response.get("Contents", [])
    except ClientError as e:
        print(f"Error listing S3 objects: {e}")
        return []


def delete_from_s3(s3_key):
    """Delete object from S3 bucket"""
    if not s3_client:
        raise Exception("S3 client not initialized")

    try:
        s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=s3_key)
        return True
    except ClientError as e:
        raise Exception(f"Failed to delete from S3: {e}")


def generate_presigned_url(s3_key, expiration=3600):
    """Generate presigned URL for S3 object download"""
    if not s3_client:
        return None

    try:
        response = s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": S3_BUCKET_NAME, "Key": s3_key},
            ExpiresIn=expiration,
        )
        return response
    except ClientError as e:
        print(f"Error generating presigned URL: {e}")
        return None


def get_unique_filename(existing_keys, filename):
    """Generate unique filename if file already exists in S3"""
    counter = 1
    original_filename = filename
    base_name, ext = os.path.splitext(original_filename)

    while any(key.endswith(filename) for key in existing_keys):
        filename = f"{base_name}_{counter}{ext}"
        counter += 1
    return filename


def get_file_info_s3(obj):
    """Get file information from S3 object"""
    size = obj["Size"]
    modified_time = obj["LastModified"]

    # Convert size to human readable format
    if size < 1024:
        size_str = f"{size} B"
    elif size < 1024 * 1024:
        size_str = f"{size / 1024:.1f} KB"
    else:
        size_str = f"{size / (1024 * 1024):.1f} MB"

    return {"size": size_str, "modified": modified_time.strftime("%Y-%m-%d %H:%M:%S")}


def require_admin():
    """Check if user is logged in as admin"""
    if "admin_logged_in" not in session:
        return redirect(url_for("admin_login"))
    return None


def create_zip_file(folder_path, zip_name):
    """Create a ZIP file from a folder"""
    temp_dir = tempfile.gettempdir()
    zip_path = os.path.join(temp_dir, zip_name)

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, folder_path)
                zipf.write(file_path, arcname)

    return zip_path


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Admin login page"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            flash("Login successful! Welcome to admin panel.", "success")
            return redirect(url_for("admin_manage"))
        else:
            flash("Invalid username or password", "error")

    return render_template("login.html")


@app.route("/admin/logout")
def admin_logout():
    """Admin logout"""
    session.pop("admin_logged_in", None)
    flash("Logged out successfully", "success")
    return redirect(url_for("index"))


@app.route("/")
def index():
    """Landing page"""
    # Show S3 status on landing page
    s3_status = "Connected" if s3_client else "Not Available"
    return render_template("index.html", s3_status=s3_status)


@app.route("/admin/upload", methods=["GET", "POST"])
def upload_file():
    """Admin upload page with multiple file and folder support - UPLOADS TO S3"""
    auth_check = require_admin()
    if auth_check:
        return auth_check

    if request.method == "POST":
        # Check S3 availability first
        if not s3_client:
            flash("S3 upload not available. Check AWS configuration.", "error")
            return redirect(request.url)

        # Check if files were uploaded
        if "file" not in request.files:
            flash("No files selected", "error")
            return redirect(request.url)

        files = request.files.getlist("file")

        # Check if any files are selected
        if not files or all(f.filename == "" for f in files):
            flash("No files selected", "error")
            return redirect(request.url)

        # Validate each file size individually
        valid_files = []
        oversized_files = []

        for file in files:
            if file.filename != "":
                # Get file size by seeking to end
                file.seek(0, 2)  # Seek to end of file
                file_size = file.tell()
                file.seek(0)  # Reset file pointer to beginning

                # Check individual file size limit (200MB)
                if file_size > MAX_CONTENT_LENGTH:
                    oversized_files.append(
                        f"{file.filename} ({file_size / (1024*1024):.1f}MB)"
                    )
                else:
                    valid_files.append(file)

        # If any files are too large, show error and stop
        if oversized_files:
            for oversized_file in oversized_files:
                flash(
                    f"File too large: {oversized_file} - Maximum allowed: 200MB",
                    "error",
                )
            return redirect(request.url)

        # Get existing S3 objects to check for duplicates
        existing_objects = list_s3_objects()
        existing_keys = [obj["Key"] for obj in existing_objects]

        uploaded_files = []
        failed_files = []

        for file in valid_files:
            if allowed_file(file.filename):
                try:
                    # For webkitdirectory, the full path is in file.filename
                    # For regular uploads, it's just the filename
                    full_filename = file.filename

                    if "/" in full_filename:  # This is a folder upload
                        # Preserve directory structure in S3
                        folder_path = os.path.dirname(full_filename)
                        filename = secure_filename(os.path.basename(full_filename))

                        # Clean the directory path
                        clean_folder_path = (
                            folder_path.replace("..", "").replace("\\", "/").strip("/")
                        )

                        # Generate unique filename for S3
                        final_filename = get_unique_filename(existing_keys, filename)
                        final_s3_key = (
                            f"{clean_folder_path}/{final_filename}"
                            if clean_folder_path
                            else final_filename
                        )

                    else:  # Regular file upload
                        filename = secure_filename(full_filename)
                        final_filename = get_unique_filename(existing_keys, filename)
                        final_s3_key = final_filename

                    # Upload to S3
                    s3_key = upload_to_s3(
                        file,
                        final_filename,
                        os.path.dirname(final_s3_key) if "/" in final_s3_key else "",
                    )
                    uploaded_files.append(s3_key)
                    existing_keys.append(s3_key)  # Add to list to avoid conflicts

                except Exception as e:
                    failed_files.append(f"{file.filename}: {str(e)}")
            else:
                failed_files.append(f"{file.filename}: File type not allowed")

        # Show results
        if uploaded_files:
            if len(uploaded_files) == 1:
                flash(
                    f'File "{os.path.basename(uploaded_files[0])}" uploaded to S3 successfully!',
                    "success",
                )
            else:
                flash(
                    f"{len(uploaded_files)} files uploaded to S3 successfully!",
                    "success",
                )

        if failed_files:
            for error in failed_files[:5]:  # Show first 5 errors
                flash(error, "error")
            if len(failed_files) > 5:
                flash(f"... and {len(failed_files) - 5} more files failed", "error")

        return redirect(url_for("upload_file"))

    return render_template("upload.html")


@app.route("/dashboard")
@app.route("/dashboard/<path:folder_path>")
def dashboard(folder_path=""):
    """User dashboard showing files and folders from S3 with navigation support"""
    files = []
    folders = []
    image_count = 0
    document_count = 0

    # Clean folder path
    if folder_path:
        folder_path = folder_path.replace("..", "").strip("/\\")
        folder_path = folder_path.replace("\\", "/")

    # Define file type categories
    image_extensions = {
        "jpg",
        "jpeg",
        "png",
        "gif",
        "webp",
        "svg",
        "bmp",
        "tiff",
        "tif",
        "ico",
    }
    document_extensions = {
        "pdf",
        "doc",
        "docx",
        "txt",
        "xlsx",
        "xls",
        "ppt",
        "pptx",
        "odt",
        "rtf",
        "csv",
        "md",
        "epub",
    }

    # Create breadcrumb navigation
    breadcrumbs = []
    if folder_path:
        parts = folder_path.split("/")
        current_path = ""
        for part in parts:
            if part:
                current_path = f"{current_path}/{part}" if current_path else part
                breadcrumbs.append({"name": part, "path": current_path})

    # Get S3 objects
    prefix = f"{folder_path}/" if folder_path else ""
    s3_objects = list_s3_objects(prefix)

    # Track seen folders to avoid duplicates
    seen_folders = set()

    for obj in s3_objects:
        key = obj["Key"]

        # Skip if this is exactly the prefix (empty folder)
        if key == prefix:
            continue

        # Remove prefix to get relative path
        relative_path = key[len(prefix) :] if prefix else key

        # Skip if no relative path
        if not relative_path:
            continue

        # Check if this is a direct child or nested
        if "/" in relative_path:
            # This is a nested item, create folder entry
            folder_name = relative_path.split("/")[0]
            if folder_name not in seen_folders:
                seen_folders.add(folder_name)
                folder_full_path = (
                    f"{folder_path}/{folder_name}" if folder_path else folder_name
                )
                folders.append(
                    {
                        "name": folder_name,
                        "path": folder_full_path,
                        "modified": obj["LastModified"].strftime("%Y-%m-%d %H:%M:%S"),
                        "type": "folder",
                    }
                )
        else:
            # This is a direct file
            file_info = get_file_info_s3(obj)
            file_full_path = (
                f"{folder_path}/{relative_path}" if folder_path else relative_path
            )
            files.append(
                {
                    "name": relative_path,
                    "path": file_full_path,
                    "s3_key": key,
                    "size": file_info["size"],
                    "modified": file_info["modified"],
                    "type": "file",
                }
            )

            # Count file types for overall statistics
            if "." in relative_path:
                ext = relative_path.rsplit(".", 1)[1].lower()
                if ext in image_extensions:
                    image_count += 1
                elif ext in document_extensions:
                    document_count += 1

    # Combine folders and files, sort by type (folders first) then by name
    all_items = folders + files
    all_items.sort(key=lambda x: (x["type"] == "file", x["name"]))

    return render_template(
        "dashboard.html",
        files=all_items,
        image_count=image_count,
        document_count=document_count,
        current_folder=folder_path,
        breadcrumbs=breadcrumbs,
    )


@app.route("/download/<path:filename>")
def download_file(filename):
    """Download file from S3 bucket using presigned URL"""
    try:
        # Clean and normalize the filename path
        clean_filename = unquote(filename)
        clean_filename = clean_filename.replace("..", "").strip("/\\")
        clean_filename = clean_filename.replace("\\", "/")

        # Generate presigned URL for download (10 minutes expiry)
        download_url = generate_presigned_url(clean_filename, expiration=600)

        if download_url:
            return redirect(download_url)
        else:
            flash("File not found or error generating download link", "error")
            return redirect(url_for("dashboard"))

    except Exception as e:
        flash(f"Error downloading file: {str(e)}", "error")
        return redirect(url_for("dashboard"))


@app.route("/download-folder/<path:folder_path>")
def download_folder(folder_path):
    """Download entire folder as ZIP file from S3"""
    try:
        # Clean and normalize the folder path
        clean_folder_path = folder_path.replace("..", "").strip("/\\")
        clean_folder_path = clean_folder_path.replace("\\", "/")

        # Get all objects with this prefix
        prefix = f"{clean_folder_path}/"
        s3_objects = list_s3_objects(prefix)

        if not s3_objects:
            flash("Folder not found or empty", "error")
            return redirect(url_for("dashboard"))

        # Create temporary directory for download
        temp_dir = tempfile.mkdtemp()

        try:
            # Download all files from S3 to temp directory
            for obj in s3_objects:
                key = obj["Key"]
                # Create local file path maintaining structure
                local_path = os.path.join(temp_dir, key.replace(prefix, ""))
                local_dir = os.path.dirname(local_path)

                if local_dir:
                    os.makedirs(local_dir, exist_ok=True)

                # Download file from S3
                s3_client.download_file(S3_BUCKET_NAME, key, local_path)

            # Create ZIP file
            folder_name = os.path.basename(clean_folder_path) or "files"
            zip_name = f"{folder_name}.zip"
            zip_path = create_zip_file(temp_dir, zip_name)

            return send_file(
                zip_path,
                as_attachment=True,
                download_name=zip_name,
                mimetype="application/zip",
            )

        finally:
            # Cleanup temp directory
            import shutil

            shutil.rmtree(temp_dir, ignore_errors=True)

    except Exception as e:
        flash(f"Error creating ZIP file: {str(e)}", "error")
        return redirect(url_for("dashboard"))


@app.route("/admin/delete/<path:filename>", methods=["POST"])
def delete_file(filename):
    """Admin delete file from S3"""
    auth_check = require_admin()
    if auth_check:
        return auth_check

    try:
        # Clean and normalize the filename path
        clean_filename = unquote(filename)
        clean_filename = clean_filename.replace("..", "").strip("/\\")
        clean_filename = clean_filename.replace("\\", "/")

        # Delete from S3
        success = delete_from_s3(clean_filename)
        if success:
            flash(
                f'File "{os.path.basename(filename)}" deleted successfully!', "success"
            )
        else:
            flash(f"Failed to delete file", "error")

    except Exception as e:
        flash(f"Error deleting file: {str(e)}", "error")

    return redirect(url_for("admin_manage"))


@app.route("/admin/manage")
def admin_manage():
    """Admin file management page - shows S3 files"""
    auth_check = require_admin()
    if auth_check:
        return auth_check

    files = []

    # Get all S3 objects
    s3_objects = list_s3_objects()

    for obj in s3_objects:
        key = obj["Key"]
        file_info = get_file_info_s3(obj)
        files.append(
            {
                "name": os.path.basename(key),
                "path": key,
                "s3_key": key,
                "size": file_info["size"],
                "modified": file_info["modified"],
            }
        )

    # Sort files by modification time (newest first)
    files.sort(key=lambda x: x["modified"], reverse=True)

    return render_template("admin_manage.html", files=files, s3_bucket=S3_BUCKET_NAME)


@app.route("/admin/rename/<path:filename>", methods=["POST"])
def rename_file(filename):
    """Admin rename file in S3"""
    auth_check = require_admin()
    if auth_check:
        return auth_check

    new_name = request.form.get("new_name")
    if not new_name:
        flash("New filename cannot be empty", "error")
        return redirect(url_for("admin_manage"))

    try:
        # Clean and normalize the filename path
        clean_filename = unquote(filename)
        clean_filename = clean_filename.replace("..", "").strip("/\\")
        clean_filename = clean_filename.replace("\\", "/")

        new_filename = secure_filename(new_name)

        # Preserve directory structure
        directory = os.path.dirname(clean_filename)
        new_key = f"{directory}/{new_filename}" if directory else new_filename
        new_key = new_key.replace("\\", "/")

        # Check if new name already exists
        existing_objects = list_s3_objects()
        if any(obj["Key"] == new_key for obj in existing_objects):
            flash("A file with that name already exists", "error")
            return redirect(url_for("admin_manage"))

        # Copy to new location and delete old one (S3 doesn't have rename)
        s3_client.copy_object(
            Bucket=S3_BUCKET_NAME,
            CopySource={"Bucket": S3_BUCKET_NAME, "Key": clean_filename},
            Key=new_key,
        )
        s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=clean_filename)

        flash(
            f'File renamed from "{os.path.basename(filename)}" to "{new_filename}" successfully!',
            "success",
        )

    except Exception as e:
        flash(f"Error renaming file: {str(e)}", "error")

    return redirect(url_for("admin_manage"))


@app.route("/health")
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Check S3 connectivity
        if s3_client:
            s3_client.head_bucket(Bucket=S3_BUCKET_NAME)
            s3_status = "healthy"
        else:
            s3_status = "unavailable"

        return {
            "status": "healthy",
            "s3_status": s3_status,
            "bucket": S3_BUCKET_NAME,
            "timestamp": datetime.datetime.now().isoformat(),
        }, 200
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat(),
        }, 500


@app.errorhandler(413)
def too_large(e):
    """Handle file too large error"""
    flash("File is too large. Maximum size per file is 200MB.", "error")
    return redirect(url_for("upload_file"))


if __name__ == "__main__":
    print("🚀 Starting Flask File Sharing Application...")
    print("📁 Access the application at: http://localhost:5000")
    print("🔧 Admin upload page: http://localhost:5000/admin/upload")
    print("📊 Dashboard: http://localhost:5000/dashboard")
    print("🏥 Health check: http://localhost:5000/health")
    print(f"📦 S3 Bucket: {S3_BUCKET_NAME}")
    print(f"🌍 AWS Region: {AWS_REGION}")
    print(f"🔗 S3 Status: {'✅ Connected' if s3_client else '❌ Not Available'}")

    # Production vs Development settings
    is_production = os.environ.get("FLASK_ENV") == "production"
    app.run(debug=not is_production, host="0.0.0.0", port=5000)
