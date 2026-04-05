#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include <pe-parse/parse.h>

struct AnalyzedReport {
    std::string filename;
    uint32_t machine;
    uint32_t num_sections;
    uint32_t timestamp;

    struct Section {
        std::string name;
        double entropy;
        bool is_packed;
    };
    std::vector<Section> sections;

    struct Import {
        std::string dll;
        std::string function;
        bool is_critical;
    };
    std::vector<Import> imports;

    struct StringMatch {
        std::string type;
        std::string value;
    };
    std::vector<StringMatch> strings;
};

class Analyzer {
public:
    Analyzer(const std::string& filepath);
    ~Analyzer();

    bool analyze();
    nlohmann::json get_report_json() const;

private:
    std::string m_filepath;
    AnalyzedReport m_report;
    peparse::parsed_pe* m_pe;

    void extract_header();
    void analyze_sections();
    void extract_imports();
    void scan_strings();
};
