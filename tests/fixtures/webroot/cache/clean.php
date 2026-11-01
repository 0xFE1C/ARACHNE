<?php
function render_greeting(string $name): string {
    return htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
}
echo render_greeting($_GET['name'] ?? 'guest');
