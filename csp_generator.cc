#include <regex>
#include <sstream>

#include "DynamicCSPGenerator.h"

namespace network {

DynamicCSPGenerator::DynamicCSPGenerator() {
  ResetFlags();
}

void DynamicCSPGenerator::ResetFlags() {
  has_script = false;
  has_inline_script = false;
  has_eval = false;
  has_event_handlers = false;
  has_form = false;
  has_external_resources = false;

  img_sources.clear();
  style_sources.clear();
  font_sources.clear();
}

void DynamicCSPGenerator::AnalyzeContent(const std::string& html) {
  ResetFlags();
  ExtractFeatures(html);
}

void DynamicCSPGenerator::ExtractFeatures(const std::string& html) {
  static const std::regex script_tag("<script.*?>", std::regex::icase);
  static const std::regex inline_script("<script[^>]*>[^<]+</script>",
                                        std::regex::icase);
  static const std::regex eval_expr("eval\\s*\\(", std::regex::icase);
  static const std::regex doc_write("document\\.write", std::regex::icase);
  static const std::regex event_handlers("on\\w+\\s*=", std::regex::icase);
  static const std::regex form_tag("<form", std::regex::icase);
  static const std::regex img_src("img[^>]*src=['\"]([^'\"]+)['\"]",
                                  std::regex::icase);
  static const std::regex style_href(
      "link[^>]*rel=['\"]stylesheet['\"][^>]*href=['\"]([^'\"]+)['\"]",
      std::regex::icase);
  static const std::regex font_link(
      "link[^>]*href=['\"]([^'\"]*\\.woff2?)['\"]", std::regex::icase);

  has_script = std::regex_search(html, script_tag);
  has_inline_script = std::regex_search(html, inline_script);
  has_eval =
      std::regex_search(html, eval_expr) || std::regex_search(html, doc_write);
  has_event_handlers = std::regex_search(html, event_handlers);
  has_form = std::regex_search(html, form_tag);

  std::smatch match;
  std::string::const_iterator search_start(html.cbegin());

  // Collect image sources
  while (std::regex_search(search_start, html.cend(), match, img_src)) {
    img_sources.insert(match[1]);
    search_start = match.suffix().first;
  }

  search_start = html.cbegin();
  while (std::regex_search(search_start, html.cend(), match, style_href)) {
    style_sources.insert(match[1]);
    search_start = match.suffix().first;
  }

  search_start = html.cbegin();
  while (std::regex_search(search_start, html.cend(), match, font_link)) {
    font_sources.insert(match[1]);
    search_start = match.suffix().first;
  }
}

std::string DynamicCSPGenerator::GenerateCSP(bool is_malicious) {
  if (is_malicious) {
    return "default-src 'none'; script-src 'none'; object-src 'none'; "
           "style-src 'none'; img-src 'none'; font-src 'none'; connect-src "
           "'none'; form-action 'none'; frame-ancestors 'none'; base-uri "
           "'none'; report-uri /csp-report;";
  }

  std::ostringstream csp;
  csp << "default-src 'self';";

  if (has_script) {
    if (has_inline_script || has_eval || has_event_handlers) {
      csp << " script-src 'none';";
    } else {
      csp << " script-src 'self' https://trusted.cdn.com;";
    }
  } else {
    csp << " script-src 'none'; object-src 'none';";
  }

  if (has_form) {
    csp << " form-action 'self';";
  }

  if (!img_sources.empty()) {
    csp << " img-src 'self'";
    for (const auto& src : img_sources) {
      if (src.find("http") == 0) {
        csp << " " << src;
      }
    }
    csp << ";";
  }

  if (!style_sources.empty()) {
    csp << " style-src 'self'";
    for (const auto& src : style_sources) {
      if (src.find("http") == 0) {
        csp << " " << src;
      }
    }
    if (has_inline_script) {
      csp << " 'unsafe-inline'";
    }
    csp << ";";
  }

  if (!font_sources.empty()) {
    csp << " font-src 'self'";
    for (const auto& src : font_sources) {
      if (src.find("http") == 0) {
        csp << " " << src;
      }
    }
    csp << ";";
  }

  csp << " report-uri /csp-report;";
  return csp.str();
}

}  
