# Styleguide

This document describes the coding style used in this project.

## CSS

### Use `ch` units for non-text sizes

Use `ch` units for sizes that are not related to text:

```css
body {
  /* ~80 characters wide */
  max-width: 80ch;

  /* ~2 characters of padding */
  padding: 2ch;
}
```

In CSS, `1ch` is roughly equal to the width of the `0` character in the current font. This creates a measurement that's inherently connected to  text content.

See <https://web.dev/learn/css/sizing#relative_lengths> for more information.

### Use `em` units for text sizes

Use `em` units for text sizes:

```css
header .title {
  font-size: 1.25em;
}
```

In CSS, `1em` is equal to the font size of the current element, and `1.25em` is 25% larger than the current font size. This creates a measurement that's inherently connected to the font size of the text.

See <https://web.dev/learn/css/sizing#relative_lengths> for more information.
