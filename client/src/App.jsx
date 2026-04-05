import { useState, useCallback } from 'react';
import { UploadCloud, ShieldAlert, CheckCircle, Activity, Search, AlertTriangle, FileCode2 } from 'lucide-react';
import { cn } from './lib/utils';
import axios from 'axios';

function App() {
  const [file, setFile] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [report, setReport] = useState(null);
  const [errorToast, setErrorToast] = useState(null);
  const [loadingStep, setLoadingStep] = useState(0);

  const loadingMessages = [
    "[OK] Dissecting Headers...",
    "[OK] Calculating Entropy...",
    "[OK] Extracting Imports...",
    "[OK] Scanning Strings...",
    "[OK] Building Final Report..."
  ];

  const handleDrag = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setIsDragging(true);
    } else if (e.type === "dragleave") {
      setIsDragging(false);
    }
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const selectedFile = e.dataTransfer.files[0];
      handleFile(selectedFile);
    }
  }, []);

  const handleFileInput = (e) => {
    if (e.target.files && e.target.files[0]) {
      handleFile(e.target.files[0]);
    }
  };

  const showError = (message) => {
    setErrorToast(message);
    setTimeout(() => setErrorToast(null), 5000);
  };

  const handleFile = async (selectedFile) => {
    setFile(selectedFile);
    setIsAnalyzing(true);
    setReport(null);
    setLoadingStep(0);
    setErrorToast(null);

    // Simulate loading steps for visual effect
    const loadingInterval = setInterval(() => {
      setLoadingStep((prev) => {
        if (prev < loadingMessages.length - 1) return prev + 1;
        clearInterval(loadingInterval);
        return prev;
      });
    }, 800);

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const response = await axios.post('http://localhost:3000/api/analyze', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      clearInterval(loadingInterval);
      setLoadingStep(loadingMessages.length - 1);
      
      // Artificial delay to show the final loading message
      setTimeout(() => {
        setReport(response.data);
        setIsAnalyzing(false);
      }, 500);
      
    } catch (err) {
      clearInterval(loadingInterval);
      setIsAnalyzing(false);
      showError(err.response?.data?.error || "Malformed Binary or Analysis Failed");
      setFile(null);
    }
  };

  const calculateRiskScore = (data) => {
    if (!data) return 0;
    let score = 0;
    
    // Check packed sections
    const packedSections = data.sections?.filter(s => s.entropy > 7.2) || [];
    if (packedSections.length > 0) score += 30;
    
    // Check critical imports
    const criticalImports = data.imports?.filter(i => i.is_critical) || [];
    score += Math.min(criticalImports.length * 10, 50); // Cap at 50 points for imports
    
    // Suspicious Strings
    const suspiciousStrings = data.strings?.filter(s => s.type === "Suspicious" || s.type === "URL" || s.type === "IP") || [];
    score += Math.min(suspiciousStrings.length * 5, 20); // Cap at 20 points
    
    return Math.min(score, 100);
  };

  const riskScore = calculateRiskScore(report);

  return (
    <div className="min-h-screen bg-cyber-bg text-cyber-text p-6 font-sans">
      <header className="max-w-6xl mx-auto mb-10 flex items-center gap-3 border-b border-cyber-border pb-6">
        <Activity className="h-8 w-8 text-cyber-primary" />
        <h1 className="text-3xl tracking-tighter font-mono font-bold">
          Binary<span className="text-cyber-primary">Eye</span>
        </h1>
      </header>

      <main className="max-w-6xl mx-auto flex flex-col gap-8">
        
        {/* Error Toast */}
        {errorToast && (
          <div className="fixed top-6 right-6 bg-cyber-error/10 border border-cyber-error text-cyber-error px-4 py-3 rounded-md shadow-lg flex items-center gap-3 z-50 animate-in slide-in-from-top-2">
            <AlertTriangle className="h-5 w-5" />
            <p className="font-mono text-sm">{errorToast}</p>
          </div>
        )}

        {!report && !isAnalyzing && (
          <div 
            className={cn(
              "border-2 border-dashed rounded-xl p-20 flex flex-col items-center justify-center text-center transition-all duration-300 bg-cyber-panel/50",
              isDragging 
                ? "border-cyber-primary scale-[1.02] bg-cyber-primary/5 shadow-[0_0_30px_rgba(59,130,246,0.2)]" 
                : "border-cyber-border hover:border-cyber-primary/50"
            )}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            <div className="bg-cyber-bg p-4 rounded-full mb-6 border border-cyber-border shadow-inner">
              <UploadCloud className="h-10 w-10 text-cyber-primary" />
            </div>
            <h3 className="text-2xl font-semibold mb-2">Initialize Analysis</h3>
            <p className="text-cyber-text-muted mb-8 max-w-md">
              Drag and drop an executable (.exe, .dll) to begin static analysis engine sequence.
            </p>
            <label className="relative cursor-pointer bg-cyber-primary hover:bg-cyber-primary/90 text-white px-8 py-3 rounded-md font-mono text-sm font-medium transition-colors shadow-[0_0_15px_rgba(59,130,246,0.4)]">
              <span>Select Binary Payload</span>
              <input 
                type="file" 
                className="hidden" 
                onChange={handleFileInput}
                accept=".exe,.dll,.sys,.bin"
              />
            </label>
          </div>
        )}

        {isAnalyzing && (
          <div className="border border-cyber-border rounded-xl p-8 bg-cyber-panel shadow-xl font-mono relative overflow-hidden">
             {/* Scanning Line Animation */}
             <div className="absolute top-0 left-0 w-full h-0.5 bg-cyber-primary opacity-50 shadow-[0_0_8px_#3b82f6] animate-[scan_2s_ease-in-out_infinite]" />
             
             <div className="flex items-center gap-4 mb-6 text-cyber-primary">
                <Activity className="h-6 w-6 animate-pulse" />
                <h2 className="text-xl">Engine Analyzing: {file?.name}</h2>
             </div>

             <div className="bg-cyber-bg border border-cyber-border rounded-md p-6 h-64 overflow-y-auto terminal-scroll space-y-2">
                {loadingMessages.map((msg, index) => (
                  <div 
                    key={index} 
                    className={cn(
                      "transition-opacity duration-300",
                      index <= loadingStep ? "opacity-100" : "opacity-0"
                    )}
                  >
                    <span className="text-cyber-accent">root@binary-eye:~#</span> {msg}
                  </div>
                ))}
                {loadingStep === loadingMessages.length - 1 && (
                   <div className="text-cyber-primary animate-pulse mt-4">_</div>
                )}
             </div>
          </div>
        )}

        {report && (
          <div className="space-y-6 animate-in fade-in zoom-in-95 duration-500">
            {/* Header Stats */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="col-span-1 md:col-span-3 bg-cyber-panel border border-cyber-border p-6 rounded-xl flex flex-col justify-between">
                <div>
                  <div className="flex items-center gap-2 text-cyber-text-muted mb-2">
                    <FileCode2 className="h-4 w-4" />
                    <span className="font-mono text-sm uppercase tracking-wider">Analyzed Target</span>
                  </div>
                  <h2 className="text-2xl font-mono truncate text-cyber-primary">{report.filename || 'Unknown'}</h2>
                </div>
                <div className="flex gap-6 mt-6 border-t border-cyber-border pt-4">
                   <div>
                     <p className="text-cyber-text-muted text-xs font-mono mb-1">MACHINE</p>
                     <p className="font-mono">{report.machine}</p>
                   </div>
                   <div>
                     <p className="text-cyber-text-muted text-xs font-mono mb-1">DATE STAMP</p>
                     <p className="font-mono">{report.timestamp}</p>
                   </div>
                   <div>
                     <p className="text-cyber-text-muted text-xs font-mono mb-1">SECTIONS</p>
                     <p className="font-mono">{report.num_sections}</p>
                   </div>
                </div>
              </div>
              
              {/* Risk Gauge */}
              <div className="bg-cyber-panel border border-cyber-border p-6 rounded-xl flex flex-col items-center justify-center text-center">
                 <p className="text-cyber-text-muted text-sm font-mono mb-4 uppercase tracking-widest">Threat Score</p>
                 <div className="relative h-32 w-32 flex items-center justify-center">
                    <svg className="absolute inset-0 h-full w-full transform -rotate-90">
                      <circle cx="64" cy="64" r="56" fill="none" stroke="var(--color-cyber-border)" strokeWidth="8" />
                      <circle 
                        cx="64" 
                        cy="64" 
                        r="56" 
                        fill="none" 
                        stroke={riskScore > 70 ? 'var(--color-cyber-error)' : riskScore > 30 ? 'var(--color-cyber-warning)' : 'var(--color-cyber-accent)'} 
                        strokeWidth="8" 
                        strokeDasharray="351.8" 
                        strokeDashoffset={351.8 - (351.8 * riskScore) / 100}
                        className="transition-all duration-1000 ease-out"
                      />
                    </svg>
                    <span className="text-4xl font-mono font-bold tracking-tighter">
                      {riskScore}
                    </span>
                 </div>
                 <p className={cn("mt-4 text-xs font-mono font-bold uppercase", 
                    riskScore > 70 ? "text-cyber-error" : riskScore > 30 ? "text-cyber-warning" : "text-cyber-accent"
                 )}>
                   {riskScore > 70 ? "High Risk" : riskScore > 30 ? "Suspicious" : "Clean"}
                 </p>
              </div>
            </div>

            {/* Main Tabs/Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              
              {/* Sections Table (Entropy) */}
              <div className="bg-cyber-panel border border-cyber-border rounded-xl p-6 h-96 flex flex-col">
                <h3 className="font-mono text-lg mb-4 flex items-center gap-2">
                  <span className="w-2 h-2 bg-cyber-primary rounded-full" />
                  Section Headers & Entropy
                </h3>
                <div className="flex-1 overflow-y-auto terminal-scroll border border-cyber-border rounded border-t-0 border-x-0">
                  <table className="w-full text-left border-collapse">
                    <thead className="sticky top-0 bg-cyber-bg font-mono text-xs text-cyber-text-muted">
                      <tr>
                        <th className="p-3 border-b border-cyber-border">Name</th>
                        <th className="p-3 border-b border-cyber-border text-right">Entropy</th>
                        <th className="p-3 border-b border-cyber-border text-center">Status</th>
                      </tr>
                    </thead>
                    <tbody className="font-mono text-sm divide-y divide-cyber-border/50">
                      {report.sections?.map((sec, i) => {
                         const isPacked = sec.entropy > 7.2;
                         return (
                          <tr key={i} className="hover:bg-cyber-bg/50 transition-colors">
                            <td className="p-3">{sec.name}</td>
                            <td className={cn("p-3 text-right", isPacked && "text-cyber-error font-bold")}>
                              {sec.entropy.toFixed(3)}
                            </td>
                            <td className="p-3 text-center">
                              {isPacked ? (
                                <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-cyber-error/10 text-cyber-error text-xs">
                                  <ShieldAlert className="h-3 w-3" /> Packed
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-cyber-accent/10 text-cyber-accent text-xs">
                                  <CheckCircle className="h-3 w-3" /> OK
                                </span>
                              )}
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Imports Table */}
              <div className="bg-cyber-panel border border-cyber-border rounded-xl p-6 h-96 flex flex-col">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-mono text-lg flex items-center gap-2">
                    <span className="w-2 h-2 bg-cyber-accent rounded-full" />
                    Import Address Table
                  </h3>
                  <div className="relative">
                    <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-cyber-text-muted" />
                    <input 
                      type="text" 
                      placeholder="Search APIs..." 
                      className="bg-cyber-bg border border-cyber-border rounded-md pl-8 pr-3 py-1 text-xs font-mono focus:outline-none focus:border-cyber-primary"
                    />
                  </div>
                </div>
                <div className="flex-1 overflow-y-auto terminal-scroll border border-cyber-border rounded border-t-0 border-x-0">
                  <table className="w-full text-left border-collapse">
                    <thead className="sticky top-0 bg-cyber-bg font-mono text-xs text-cyber-text-muted">
                      <tr>
                        <th className="p-3 border-b border-cyber-border">DLL</th>
                        <th className="p-3 border-b border-cyber-border">API Call</th>
                      </tr>
                    </thead>
                    <tbody className="font-mono text-sm divide-y divide-cyber-border/50">
                      {report.imports?.map((imp, i) => (
                          <tr key={i} className="hover:bg-cyber-bg/50 transition-colors">
                            <td className="p-3 text-cyber-text-muted">{imp.dll}</td>
                            <td className="p-3 flex items-center gap-2">
                              {imp.function}
                              {imp.is_critical && (
                                <AlertTriangle className="h-3 w-3 text-cyber-error" title="Critical API" />
                              )}
                            </td>
                          </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

            </div>

            {/* Suspicious Strings */}
            <div className="bg-cyber-panel border border-cyber-border rounded-xl p-6">
               <h3 className="font-mono text-lg mb-4 flex items-center gap-2">
                  <span className="w-2 h-2 bg-cyber-warning rounded-full" />
                  IOCs & Suspicious Strings
                </h3>
                <div className="flex flex-wrap gap-3">
                  {report.strings?.length > 0 ? report.strings.map((str, i) => {
                     // Determine styling based on type
                     let badgeStyle = "bg-cyber-bg border border-cyber-border text-cyber-text";
                     if (str.type === "URL") badgeStyle = "bg-cyber-primary/10 border border-cyber-primary/30 text-cyber-primary";
                     if (str.type === "IP") badgeStyle = "bg-cyber-accent/10 border border-cyber-accent/30 text-cyber-accent";
                     if (str.type === "Suspicious") badgeStyle = "bg-cyber-error/10 border border-cyber-error/30 text-cyber-error";

                     return (
                      <div key={i} className={cn("px-3 py-1.5 rounded-md font-mono text-xs flex flex-col gap-1", badgeStyle)}>
                        <span className="opacity-70 text-[10px] uppercase tracking-widest">{str.type}</span>
                        <span className="break-all">{str.value}</span>
                      </div>
                     )
                  }) : (
                     <p className="text-cyber-text-muted font-mono text-sm italic">No suspicious strings or IOCs detected.</p>
                  )}
                </div>
            </div>

            <div className="text-center pt-8">
              <button 
                onClick={() => setReport(null)}
                className="bg-transparent border border-cyber-primary text-cyber-primary hover:bg-cyber-primary/10 px-8 py-2 rounded-md font-mono text-sm font-medium transition-colors"
              >
                Analyze Another Binary
              </button>
            </div>

          </div>
        )}

      </main>
      
      {/* CSS Animation defined locally for convenience */}
      <style>{`
        @keyframes scan {
          0% { top: 0%; opacity: 0; }
          10% { opacity: 1; }
          90% { opacity: 1; }
          100% { top: 100%; opacity: 0; }
        }
      `}</style>
    </div>
  )
}

export default App
