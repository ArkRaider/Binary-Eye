#include "Analyzer.h"
#include <fstream>
#include <cmath>
#include <regex>
#include <iostream>
#include <unordered_set>
#include <unordered_map>

using json = nlohmann::json;
using namespace peparse;

Analyzer::Analyzer(const std::string& filepath) : m_filepath(filepath), m_pe(nullptr) {
    m_report.filename = filepath;
}

Analyzer::~Analyzer() {
    if (m_pe) {
        DestructParsedPE(m_pe);
    }
}

bool Analyzer::analyze() {
    m_pe = ParsePEFromFile(m_filepath.c_str());
    if (!m_pe) {
        std::cerr << "Failed to parse PE file: " << m_filepath << std::endl;
        return false;
    }

    extract_header();
    analyze_sections();
    extract_imports();
    scan_strings();

    return true;
}

void Analyzer::extract_header() {
    m_report.machine = m_pe->peHeader.nt.FileHeader.Machine;
    m_report.num_sections = m_pe->peHeader.nt.FileHeader.NumberOfSections;
    m_report.timestamp = m_pe->peHeader.nt.FileHeader.TimeDateStamp;
}

double calculate_entropy(const std::vector<uint8_t>& data) {
    if (data.empty()) return 0.0;
    std::unordered_map<uint8_t, size_t> counts;
    for (uint8_t b : data) counts[b]++;
    
    double entropy = 0.0;
    double size = data.size();
    for (auto& pair : counts) {
        double p = pair.second / size;
        entropy -= p * log2(p);
    }
    return entropy;
}

void Analyzer::analyze_sections() {
    struct SecData { std::string name; uint32_t offset; uint32_t size; };
    std::vector<SecData> secs;
    
    auto cb = [](void *cbd, const VA &v, const std::string &name, const image_section_header &sec, const bounded_buffer *b) -> int {
        auto* secs_ptr = static_cast<std::vector<SecData>*>(cbd);
        secs_ptr->push_back({name, sec.PointerToRawData, sec.SizeOfRawData});
        return 0;
    };
    
    IterSec(m_pe, cb, &secs);
    
    std::ifstream file(m_filepath, std::ios::binary);
    for (const auto& sec : secs) {
        AnalyzedReport::Section s;
        s.name = sec.name;
        s.entropy = 0;
        s.is_packed = false;
        
        if (sec.size > 0 && file) {
            file.seekg(sec.offset, std::ios::beg);
            std::vector<uint8_t> data(sec.size);
            file.read(reinterpret_cast<char*>(data.data()), sec.size);
            s.entropy = calculate_entropy(data);
        }
        
        if (s.entropy > 7.0) s.is_packed = true;
        m_report.sections.push_back(s);
    }
}

int import_cb(void *cbd, const VA &v, const std::string &module, const std::string &name) {
    auto* report = static_cast<AnalyzedReport*>(cbd);
    AnalyzedReport::Import imp;
    imp.dll = module;
    imp.function = name;
    
    std::unordered_set<std::string> critical = {
        "ShellExecuteA", "ShellExecuteW", "CreateRemoteThread", 
        "InternetOpenA", "InternetOpenW", "VirtualAllocEx", "LoadLibraryA", "VirtualProtect",
        "WriteProcessMemory", "HttpSendRequestA", "HttpSendRequestW", 
        "RegSetValueA", "RegSetValueW", "RegSetValueExA", "RegSetValueExW"
    };
    
    imp.is_critical = critical.count(name) > 0;
    report->imports.push_back(imp);
    return 0;
}

void Analyzer::extract_imports() {
    IterImpVAString(m_pe, import_cb, &m_report);
}

void Analyzer::scan_strings() {
    std::ifstream file(m_filepath, std::ios::binary);
    if (!file) return;
    
    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    std::string content(buffer.begin(), buffer.end());
    
    std::regex ascii_regex("[A-Za-z0-9_\\\\/:.-]{5,}");
    auto words_begin = std::sregex_iterator(content.begin(), content.end(), ascii_regex);
    auto words_end = std::sregex_iterator();
    
    std::unordered_set<std::string> suspicious = {
        "cmd.exe", "powershell", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    };
    
    std::regex ip_regex(R"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)");
    std::regex url_regex(R"(http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)");
    
    for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
        std::string match = (*i).str();
        
        if (suspicious.find(match) != suspicious.end()) {
             // Avoid duplicates for same strings
             bool exists = false;
             for(auto& s : m_report.strings) { if (s.value == match) { exists = true; break; } }
             if (!exists) m_report.strings.push_back({"Suspicious", match});
             continue;
        }
        
        if (std::regex_match(match, ip_regex)) {
             bool exists = false;
             for(auto& s : m_report.strings) { if (s.value == match) { exists = true; break; } }
             if (!exists) m_report.strings.push_back({"IP", match});
             continue;
        }
        
        if (std::regex_match(match, url_regex)) {
             bool exists = false;
             for(auto& s : m_report.strings) { if (s.value == match) { exists = true; break; } }
             if (!exists) m_report.strings.push_back({"URL", match});
             continue;
        }
    }
}

json Analyzer::get_report_json() const {
    json j;
    j["filename"] = m_report.filename;
    j["machine"] = m_report.machine;
    j["num_sections"] = m_report.num_sections;
    j["timestamp"] = m_report.timestamp;
    
    j["sections"] = json::array();
    for (const auto& s : m_report.sections) {
        j["sections"].push_back({
            {"name", s.name},
            {"entropy", s.entropy},
            {"is_packed", s.is_packed}
        });
    }
    
    j["imports"] = json::array();
    for (const auto& i : m_report.imports) {
        j["imports"].push_back({
            {"dll", i.dll},
            {"function", i.function},
            {"is_critical", i.is_critical}
        });
    }
    
    j["strings"] = json::array();
    for (const auto& s : m_report.strings) {
        j["strings"].push_back({
            {"type", s.type},
            {"value", s.value}
        });
    }
    
    return j;
}
