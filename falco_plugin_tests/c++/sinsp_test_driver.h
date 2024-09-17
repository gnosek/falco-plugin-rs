#pragma once

class SinspTestDriver;
struct SinspMetric;

#include <memory>
#include <libsinsp/plugin.h>
#include <libsinsp/sinsp.h>

#include "falco_plugin_tests/src/ffi.rs.h"

class SinspTestDriver {
public:
    SinspTestDriver():
        m_sinsp(true),
        m_metrics(&m_sinsp, METRICS_V2_PLUGINS)
        {}

    std::shared_ptr<sinsp_plugin> register_plugin(const Api* api, const char* config);
    void add_filterchecks(const std::shared_ptr<sinsp_plugin>& plugin, const char* source);
    void load_capture_file(const char* path);
    void start_capture(const char* name, const char* config);
    SinspEvent next();
    std::unique_ptr<std::string> event_field_as_string(const char* field_name, const SinspEvent& event);
    std::unique_ptr<std::vector<SinspMetric>> get_metrics();

private:
    sinsp m_sinsp;
    libs::metrics::libs_metrics_collector m_metrics;
    sinsp_filter_check_list m_filterchecks;
};

std::unique_ptr<SinspTestDriver> new_test_driver();
