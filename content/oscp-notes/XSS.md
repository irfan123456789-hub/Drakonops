---
title: "XSS"
weight: 19
---
## XSS Testing Payloads

We can test whether the page is vulnerable to XSS with the following basic XSS payload:

Code: html

```html
<script>alert(window.origin)</script>
```

&nbsp;

As some modern browsers may block the `alert()` JavaScript function in specific locations, it may be handy to know a few other basic XSS payloads to verify the existence of XSS. One such XSS payload is `<plaintext>`, which will stop rendering the HTML code that comes after it and display it as plaintext. Another easy-to-spot payload is `<script>print()</script>` that will pop up the browser print dialog, which is unlikely to be blocked by any browsers. Try using these payloads to see how each works. You may use the reset button to remove any current payloads.

&nbsp;

&nbsp;to read cokies

```
<script>console.log(document.cookie)</script>
```

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;