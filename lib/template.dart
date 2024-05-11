/// Given a template and a map of values, replaces all instances of `{{key}}`.
///
/// If any key is not found in the map, an error is thrown.
String render(String template, Map<String, String> values) {
  for (final entry in values.entries) {
    template = template.replaceAll('{{${entry.key}}}', entry.value);
  }

  if (template.contains('{{')) {
    throw ArgumentError('Missing values in template: $template');
  }

  return template;
}

/// Generates a `index.html` file from a template.
String index(
  String template, {
  required Uri server,
}) {
  return render(template, {
    'title': 'mtnlu',
    'description': 'Yet another programming blog by Matan Lurey.',
    'url': '$server',
    'content': 'Hello World!',
  });
}
