#!/usr/bin/env dart

import 'dart:io' as io;

import 'package:args/args.dart';
import 'package:mtnlu/build.dart';
import 'package:mtnlu/serve.dart';
import 'package:path/path.dart' as p;

/// Generates a static site from a template and static files.
///
/// ## Usage
///
/// ```shell
/// ./mtnlu.dart
/// ```
void main(List<String> args) async {
  final results = _parser(rootPath: p.current).parse(args);

  if (results['help'] as bool) {
    io.stderr.writeln(_parser(rootPath: p.current).usage);
    return;
  }

  final templatePath = results['template'] as String;
  final outputPath = results['output'] as String;
  final staticPath = results['static'] as String;

  if (results['serve'] as bool) {
    final server = await HttpPreviewServer.start(
      templatePath: templatePath,
      outputPath: outputPath,
      staticPath: staticPath,
    );

    io.stdout.writeln('Serving at http://localhost:${server.port}');

    // Wait for SIGINT (Ctrl+C) to stop the server.
    await io.ProcessSignal.sigint.watch().first;

    io.stderr.writeln();
    io.stderr.writeln('Shutting down server...');
    await server.close();
  } else {
    await build(
      templatePath: templatePath,
      outputPath: outputPath,
      staticPath: staticPath,
      server: Uri.parse(results['server'] as String),
    );

    io.stdout.writeln('Generated index.html in $outputPath');
  }
}

ArgParser _parser({
  required String rootPath,
}) {
  return ArgParser()
    ..addFlag(
      'help',
      abbr: 'h',
      help: 'Print usage information.',
      negatable: false,
    )
    ..addFlag(
      'serve',
      help: 'Start a server to preview the static site.',
      negatable: false,
    )
    ..addOption(
      'output',
      abbr: 'o',
      help: 'Output directory',
      valueHelp: '/path/to/output',
      defaultsTo: p.join(rootPath, 'build'),
    )
    ..addOption(
      'template',
      abbr: 't',
      help: 'Template file to use',
      valueHelp: '/path/to/template.html',
      defaultsTo: p.join(rootPath, 'template.html'),
    )
    ..addOption(
      'static',
      abbr: 's',
      help: 'Directory to copy static files from',
      valueHelp: '/path/to/static',
      defaultsTo: p.join(rootPath, 'static'),
    )
    ..addOption(
      'server',
      help: 'URL of the server',
      valueHelp: 'https://yoursite.dev',
      defaultsTo: 'https://mtnlu.dev',
    );
}
