const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Ensure the local 'uploads/' directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}

// Configure multer with UUID renaming for security
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
        // Rename the uploaded file to a random UUID to prevent path traversal
        cb(null, crypto.randomUUID());
    }
});

const upload = multer({ 
    storage,
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit based on readme
});

app.post('/api/analyze', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    const uploadedFilePath = req.file.path;
    const absoluteFilePath = path.resolve(uploadedFilePath);

    // Verify Magic Bytes 'MZ' (0x4D 0x5A)
    try {
        const fd = fs.openSync(absoluteFilePath, 'r');
        const buffer = Buffer.alloc(2);
        fs.readSync(fd, buffer, 0, 2, 0);
        fs.closeSync(fd);

        if (buffer[0] !== 0x4D || buffer[1] !== 0x5A) {
            fs.unlinkSync(absoluteFilePath); // clean up
            return res.status(400).json({ error: 'Invalid file format. Must be a Windows Executable (MZ).' });
        }
    } catch (err) {
        return res.status(500).json({ error: 'Failed to read file signature.' });
    }
    
    // Resolve absolute paths dynamically for the engine and the uploaded file
    const enginePath = path.resolve(__dirname, '../engine/build/Debug/engine.exe');
    const engineCwd = path.resolve(__dirname, '../engine/build/Debug');
    const dllPath = path.resolve(__dirname, '../engine/build/Debug/pe-parse.dll');

    // Verify DLL and Engine presence
    if (!fs.existsSync(enginePath) || !fs.existsSync(dllPath)) {
        console.error('[ERROR] DLL OR ENGINE EXECUTABLE MISSING');
        console.error(`  engine.exe found: ${fs.existsSync(enginePath)}`);
        console.error(`  pe-parse.dll found: ${fs.existsSync(dllPath)}`);
    }

    console.log(`\n--- [DEBUG] NEW ANALYSIS REQUEST ---`);
    console.log(`[DEBUG] Executing Command: ${enginePath} "${absoluteFilePath}"`);
    console.log(`[DEBUG] CWD for process: ${engineCwd}`);

    // Use spawn safely and set the Current Working Directory (CWD) to help the engine find pe-parse.dll
    const engineProcess = spawn(enginePath, [absoluteFilePath], { cwd: engineCwd });

    let stdoutData = '';
    let stderrData = '';

    const timeout = setTimeout(() => {
        engineProcess.kill('SIGKILL');
    }, 10000); // 10 second timeout

    engineProcess.stdout.on('data', (data) => {
        const str = data.toString();
        console.log(`[DEBUG] [RAW STDOUT]: ${str}`);
        stdoutData += str;
    });

    engineProcess.stderr.on('data', (data) => {
        stderrData += data.toString();
    });

    engineProcess.on('close', (code) => {
        clearTimeout(timeout);

        if (fs.existsSync(absoluteFilePath)) {
            fs.unlinkSync(absoluteFilePath);
        }

        if (code !== 0) {
            console.error(`[DEBUG] C++ Analysis Engine Status Code: ${code}`);
            console.error(`[DEBUG] stderr: ${stderrData}`);
            
            if (code === null) {
                return res.status(500).json({ error: 'Analysis Engine timed out after 10 seconds.' });
            }

            // Give preference to structured JSON errors if the engine outputted any before crashing
            try {
                if (stdoutData) {
                    const parsedData = JSON.parse(stdoutData);
                    return res.status(500).json({ error: 'Engine encountered a problem', details: parsedData });
                }
            } catch (e) {
                // Not valid JSON, proceed with generic error
            }
            
            return res.status(500).json({ 
                error: 'Failed to analyze file.', 
                details: stderrData || 'Process killed or unknown error'
            });
        }

        try {
            // Success: Parse the JSON string from stdout and return as structured JSON response
            const parsedOutput = JSON.parse(stdoutData);
            res.status(200).json(parsedOutput);
        } catch (parseError) {
            console.error(`[DEBUG] Failed to parse output as JSON. Raw stdout dump:\n${stdoutData}\n--- END DUMP ---`);
            res.status(500).json({ 
                error: 'Analysis Engine returned invalid JSON output', 
                details: parseError.message 
            });
        }
    });

    engineProcess.on('error', (err) => {
        clearTimeout(timeout);
        if (fs.existsSync(absoluteFilePath)) {
            fs.unlinkSync(absoluteFilePath);
        }
        res.status(500).json({ error: 'Failed to start the engine process.', details: err.message });
    });
});

app.listen(port, () => {
    console.log(`Binary-Eye API server is running on http://localhost:${port}`);
});
