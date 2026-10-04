---
type: article
profile: sorane-okf/0.1
title: 'Accessibility of the mikaki website'
description: 'Keyboard navigation, pausing background motion, reflow and table controls, and verification scope for the public site, application guide and integration demo.'
lang: en
translation_key: accessibility
updated: 2026-10-04
---

The public website, application information pages and public integration demo aim to make information accessible across devices and input methods. [WCAG 2.2](https://www.w3.org/TR/WCAG22/) Level AA guides the design and checks.

## Navigate with a keyboard

Press Tab after opening a page to reveal “Skip to content”. Press Enter to move past repeated navigation to the main content. Links and buttons show a focus outline.

Articles separate main navigation, guides in the same section and the contents of the current page. Open the collapsed contents with Enter or Space, then use its links to reach individual headings.

## Pause background motion

Use “Pause background animation” on the homepage to stop the decorative animation. Press it again to resume. Your choice persists while browsing in the same tab. If your device requests reduced motion, the background remains still.

Article and demo content does not use moving backgrounds. Text, navigation and contents links remain available with JavaScript disabled.

## Use zoom and tables

Content stacks vertically on narrow screens. Tables and code samples scroll horizontally within their own region when necessary. Use Tab to focus a region and arrow keys to scroll it.

Links within text are underlined. Current pages, focus and login state are communicated without relying on color alone. Instructional images have alternative text.

## Verification scope and feedback

Japanese and English pages are checked with axe. Browser checks cover keyboard navigation to content, headings and tables, a 320 CSS px viewport, text-spacing overrides, reduced motion and the pause control. Demo checks include the signed-out and signed-in views.

Automated checks alone do not establish complete conformance. Physical-device checks with screen readers such as VoiceOver and NVDA remain necessary. Operating-system and passkey-authenticator confirmation screens are provided by your device.

If you encounter a barrier, use the [contact page](contact.md) to share the affected page, operation, browser and assistive technology. Public reports do not need personal information, invitation codes, active login URLs or tokens.
