Project Specification: Binary-Eye Static Sandbox
1. Project Overview
Goal: Build a full-stack static analysis dashboard that dissects Windows Portable Executable (PE) files to identify potential malware traits without execution.
Core Value: Demonstrates proficiency in C++ system programming, React UI design, and secure file handling on AWS.

2. Technical Stack
Frontend: React (Vite) with Tailwind CSS and Lucide-react icons. Use Shadcn/UI for a professional "Security Dashboard" aesthetic.

Backend API: Node.js (FastAPI/Python is an acceptable alternative) to orchestrate file uploads and manage the database.

Analysis Engine: C++17. Use the pe-parse library for robust PE header extraction.

Database: PostgreSQL (via Prisma) to store file metadata and analysis reports.

Storage: Local "Isolated" directory (Development) / AWS S3 (Production).

3. Micro-Detailed Modules
A. The C++ Analysis Engine (/engine)
The engine must be a standalone CLI tool that accepts a file path and outputs a JSON object to stdout.

Header Extraction: Capture Machine type, Number of Sections, and TimeDateStamp.

Section Analysis: Calculate Entropy for each section (.text, .data, .reloc). If entropy > 7.0, flag as "Potentially Packed/Encrypted."

Import Table (IAT): Extract a list of DLLs and Function Names. Flag "Critical Imports" like ShellExecute, CreateRemoteThread, and InternetOpen.

String Scan: Implement a basic regex search for IP addresses, URLs, and common malicious strings (e.g., "cmd.exe", "powershell", "Software\Microsoft\Windows\CurrentVersion\Run").

B. The Backend API (/server)
Endpoint POST /analyze: 1. Receive file via multer.
2. Save file with a UUID filename (to prevent path traversal).
3. Use child_process.exec (Node) or subprocess (Python) to run the C++ Engine.
4. Parse the JSON output and save to PostgreSQL.

Security: Implement a 10MB file limit and a "Magic Byte" check to ensure only MZ (Windows Executables) are processed.

C. The Frontend Dashboard (/client)
State 1 (Upload): A drag-and-drop zone with a "Cyber" glow effect.

State 2 (Processing): A terminal-style log showing the analysis steps (e.g., "Extracting Strings...", "Calculating Entropy...").

State 3 (Report): * Risk Meter: A gauge based on a weighted score (Imports: 30%, Entropy: 40%, Strings: 30%).

Interactive Table: A searchable list of all imported DLLs.

Hex Preview: A read-only view of the first 256 bytes.

*the user needs to compile the engine locally to make the app work. This proves you understand Build Pipelines*

4. Security Constraints (Crucial)
Non-Execution Policy: The backend must never chmod +x the uploaded file.

Path Sanitization: All filenames must be hashed (SHA-256) before being saved to disk to prevent malicious filenames from breaking the system.

Environment: The C++ engine must run in a restricted permission environment (User-level, no Network access).

5. Development Roadmap
Step 1: Create the C++ PE Parser and verify it outputs valid JSON.

Step 2: Build the Node.js wrapper that can call the C++ binary.

Step 3: Design the React Dashboard to visualize the JSON data.

## System Architecture Diagram

```mermaid
graph TD
    Client[React Dashboard UI\nHigh Level] -->|POST /api/analyze\nUploads .exe / .dll| Backend[Node.js Express\nMid Level Bridge]
    Backend -->|Validates MZ Bytes| Sanitize[Storage/Sanitization\Renames to UUID]
    Sanitize -->|Child Process Spawn| Engine[C++ Analyzer.cpp\nLow Level Engine]
    Engine -->|Parses Headers, Sections,\nStrings, Imports| Engine
    Engine -->|Outputs JSON| Backend
    Backend -->|Returns JSON\n(or 500 error on 10s timeout)| Client
    Client -->|Renders Visualizations| UI[Risk Gauge, Tables, Cloud]
```
