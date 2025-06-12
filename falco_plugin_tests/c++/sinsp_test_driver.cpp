#include <mutex>
#include <string>

#include "falco_plugin_tests/c++/sinsp_test_driver.h"

static std::mutex s_sinsp_lock;

const char *SinspEvent::scap_event() const noexcept {
  auto sinsp_event = (const sinsp_evt *)evt;
  return reinterpret_cast<const char *>(sinsp_event->get_scap_evt());
}

std::unique_ptr<SinspTestDriver> new_test_driver() {
  std::scoped_lock m(s_sinsp_lock);

  libsinsp_logger()->add_stdout_log();
  libsinsp_logger()->set_severity(sinsp_logger::SEV_TRACE);
  return std::make_unique<SinspTestDriver>();
}

std::shared_ptr<sinsp_plugin>
SinspTestDriver::register_plugin(const Api *api, const char *config) {
  std::scoped_lock m(s_sinsp_lock);
  std::string err;

  auto plugin =
      m_sinsp.register_plugin(reinterpret_cast<const plugin_api *>(api));
  if (!plugin->init(config, err)) {
    throw sinsp_exception(err);
  }

  return plugin;
}

void SinspTestDriver::add_filterchecks(
    const std::shared_ptr<sinsp_plugin> &plugin, const char *source) {
  std::scoped_lock m(s_sinsp_lock);
  if (plugin->caps() & CAP_EXTRACTION &&
      sinsp_plugin::is_source_compatible(plugin->extract_event_sources(),
                                         source)) {
    m_filterchecks.add_filter_check(m_sinsp.new_generic_filtercheck());
    m_filterchecks.add_filter_check(sinsp_plugin::new_filtercheck(plugin));
  }
}

void SinspTestDriver::load_capture_file(const char *path) {
  std::scoped_lock m(s_sinsp_lock);
  m_sinsp.open_savefile(path, 0);
  m_sinsp.start_capture();
}

void SinspTestDriver::start_capture(const char *name, const char *config) {
  std::scoped_lock m(s_sinsp_lock);
  m_sinsp.open_plugin(name, config,
                      sinsp_plugin_platform::SINSP_PLATFORM_GENERIC);
  m_sinsp.start_capture();
}

SinspEvent SinspTestDriver::next() {
  std::scoped_lock m(s_sinsp_lock);
  sinsp_evt *evt;
  int rc = m_sinsp.next(&evt);

  return SinspEvent{rc, reinterpret_cast<char *>(evt)};
}

std::unique_ptr<std::string>
SinspTestDriver::event_field_as_string(const char *field_name,
                                       const SinspEvent &event) {
  std::scoped_lock m(s_sinsp_lock);
  sinsp_evt *evt = reinterpret_cast<sinsp_evt *>(event.evt);

  if (evt == nullptr) {
    throw sinsp_exception("The event class is NULL");
  }

  std::unique_ptr<sinsp_filter_check> chk(
      m_filterchecks.new_filter_check_from_fldname(field_name, &m_sinsp,
                                                   false));
  if (chk == nullptr) {
    throw sinsp_exception("The field " + std::string(field_name) +
                          " is not a valid field.");
  }
  // we created a filter check starting from the field name so if we arrive here
  // we will find it for sure
  chk->parse_field_name(field_name, true, false);

  const char *result = chk->tostring(evt);
  if (result == nullptr) {
    throw sinsp_exception("The field " + std::string(field_name) + " is NULL");
  }

  return std::make_unique<std::string>(result);
}

std::unique_ptr<std::string>
SinspTestDriver::event_field_as_string_with_offsets(const char *field_name,
                                                    const SinspEvent &event,
                                                    uint32_t &start,
                                                    uint32_t &length) {
  std::scoped_lock m(s_sinsp_lock);
  sinsp_evt *evt = reinterpret_cast<sinsp_evt *>(event.evt);

  if (evt == nullptr) {
    throw sinsp_exception("The event class is NULL");
  }

  std::unique_ptr<sinsp_filter_check> chk(
      m_filterchecks.new_filter_check_from_fldname(field_name, &m_sinsp,
                                                   false));
  if (chk == nullptr) {
    throw sinsp_exception("The field " + std::string(field_name) +
                          " is not a valid field.");
  }
  // we created a filter check starting from the field name so if we arrive here
  // we will find it for sure
  chk->parse_field_name(field_name, true, false);

  const char *result = chk->tostring(evt);
  if (result == nullptr) {
    throw sinsp_exception("The field " + std::string(field_name) + " is NULL");
  }

  std::string s = result;

  // getting a string value from an extracted value is convoluted enough; just
  // extract the field again, ignoring the value and only getting the offsets
  std::vector<extract_value_t> values;
  std::vector<extract_offset_t> offsets;
  chk->extract_with_offsets(evt, values, offsets);

  if (!offsets.empty()) {
    start = offsets[0].start;
    length = offsets[0].length;
  }

  return std::make_unique<std::string>(s);
}

std::unique_ptr<std::vector<SinspMetric>> SinspTestDriver::get_metrics() {
  std::scoped_lock m(s_sinsp_lock);
  m_metrics.snapshot();

  std::vector<SinspMetric> metrics;
  for (const auto &m : m_metrics.get_metrics()) {
    SinspMetric metric;
    metric.name = std::make_unique<std::string>(m.name);
    metric.value = m.value.u64;

    metrics.emplace_back(std::move(metric));
  }

  return std::make_unique<std::vector<SinspMetric>>(std::move(metrics));
}
