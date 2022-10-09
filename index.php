<?php

error_reporting( error_reporting() & ~E_NOTICE );

//Opciones de seguridad
$permitir_borrado = true; 
$permitir_upload = true;
$permitir_crear_carpeta = true;
$permitir_link_directo = true;
$permitir_mostrar_carpetas = true;

$patrones_prohibidos = ['*.php'];  // No se permite subir archivos PHP
$patrones_ocultos = ['*.php','.*']; // Archivos ocultos

$PASSWORD = 'Seminario2022';  // Clave para acceder al sharepoint (opcional)

if($PASSWORD) {

	session_start();
	if(!$_SESSION['_sfm_allowed']) {
		// se agregan bytes aleatorios para evitar ataques de timing
		$t = bin2hex(openssl_random_pseudo_bytes(10));
		if($_POST['p'] && sha1($t.$_POST['p']) === sha1($t.$PASSWORD)) {
			$_SESSION['_sfm_allowed'] = true;
			header('Location: ?');
		}
		echo '<html><body><form action=? method=post>Por favor ingrese la contraseña:<input type=password name=p autofocus/></form></body></html>';
		exit;
	}
}

setlocale(LC_ALL,'en_US.UTF-8');

$tmp_dir = dirname($_SERVER['SCRIPT_FILENAME']);
if(DIRECTORY_SEPARATOR==='\\') $tmp_dir = str_replace('/',DIRECTORY_SEPARATOR,$tmp_dir);
$tmp = obtener_ruta_absoluta($tmp_dir . '/' .$_REQUEST['file']);

if($tmp === false)
	err(404,'Carpeta o archivo no encontrados');
if(substr($tmp, 0,strlen($tmp_dir)) !== $tmp_dir)
	err(403,"Prohibido");
if(strpos($_REQUEST['file'], DIRECTORY_SEPARATOR) === 0)
	err(403,"Prohibido");
if(preg_match('@^.+://@',$_REQUEST['file'])) {
	err(403,"Prohibido");
}


if(!$_COOKIE['_sfm_xsrf'])
	setcookie('_sfm_xsrf',bin2hex(openssl_random_pseudo_bytes(16)));
if($_POST) {
	if($_COOKIE['_sfm_xsrf'] !== $_POST['xsrf'] || !$_POST['xsrf'])
		err(403,"Fallo de XSRF");
}

$file = $_REQUEST['file'] ?: '.';

if($_GET['do'] == 'list') {
	if (is_dir($file)) {
		$directory = $file;
		$result = [];
		$files = array_diff(scandir($directory), ['.','..']);
		foreach ($files as $entrada) if (!entrada_ignorada($entrada, $permitir_mostrar_carpetas, $patrones_ocultos)) {
			$i = $directory . '/' . $entrada;
			$stat = stat($i);
			$result[] = [
				'mtime' => $stat['mtime'],
				'size' => $stat['size'],
				'name' => basename($i),
				'path' => preg_replace('@^\./@', '', $i),
				'is_dir' => is_dir($i),
				'is_deleteable' => $permitir_borrado && ((!is_dir($i) && is_writable($directory)) ||
														(is_dir($i) && is_writable($directory) && es_borrable_recursivamente($i))),
				'is_readable' => is_readable($i),
				'is_writable' => is_writable($i),
				'is_executable' => is_executable($i),
			];
		}
		usort($result,function($f1,$f2){
			$f1_key = ($f1['is_dir']?:2) . $f1['name'];
			$f2_key = ($f2['is_dir']?:2) . $f2['name'];
			return $f1_key > $f2_key;
		});
	} else {
		err(412,"No es una carpeta");
	}
	echo json_encode(['success' => true, 'is_writable' => is_writable($file), 'results' =>$result]);
	exit;
} elseif ($_POST['do'] == 'delete') {
	if($permitir_borrado) {
		rmrf($file);
	}
	exit;
} elseif ($_POST['do'] == 'mkdir' && $permitir_crear_carpeta) {
	// se filtran las barras invertidas para evitar argumentos tipo './../outside'
	$dir = $_POST['name'];
	$dir = str_replace('/', '', $dir);
	if(substr($dir, 0, 2) === '..')
	    exit;
	chdir($file);
	@mkdir($_POST['name']);
	exit;
} elseif ($_POST['do'] == 'upload' && $permitir_upload) {
	foreach($patrones_prohibidos as $patron)
		if(fnmatch($patron, $_FILES['file_data']['name']))
			err(403,"Los archivos de este tipo no están permitidos.");

	$res = move_uploaded_file($_FILES['file_data']['tmp_name'], $file.'/'.$_FILES['file_data']['name']);
	exit;
} elseif ($_GET['do'] == 'download') {
	foreach($patrones_prohibidos as $patron)
		if(fnmatch($patron, $file))
			err(403,"Los archivos de este tipo no están permitidos.");

	$filename = basename($file);
	$finfo = finfo_open(FILEINFO_MIME_TYPE);
	header('Content-Type: ' . finfo_file($finfo, $file));
	header('Content-Length: '. filesize($file));
	header(sprintf('Content-Disposition: attachment; filename=%s',
		strpos('MSIE',$_SERVER['HTTP_REFERER']) ? rawurlencode($filename) : "\"$filename\"" ));
	ob_flush();
	readfile($file);
	exit;
}

function entrada_ignorada($entrada, $permitir_mostrar_carpetas, $patrones_ocultos) {
	if ($entrada === basename(__FILE__)) {
		return true;
	}

	if (is_dir($entrada) && !$permitir_mostrar_carpetas) {
		return true;
	}
	foreach($patrones_ocultos as $patron) {
		if(fnmatch($patron,$entrada)) {
			return true;
		}
	}
	return false;
}

function rmrf($dir) {
	if(is_dir($dir)) {
		$archivos = array_diff(scandir($dir), ['.','..']);
		foreach ($archivos as $archivo)
			rmrf("$dir/$archivo");
		rmdir($dir);
	} else {
		unlink($dir);
	}
}
function es_borrable_recursivamente($d) {
	$pila = [$d];
	while($dir = array_pop($pila)) {
		if(!is_readable($dir) || !is_writable($dir))
			return false;
		$archivos = array_diff(scandir($dir), ['.','..']);
		foreach($archivos as $archivo) if(is_dir($archivo)) {
			$pila[] = "$dir/$archivo";
		}
	}
	return true;
}

// de: http://php.net/manual/en/function.realpath.php#84012
function obtener_ruta_absoluta($ruta) {
        $ruta = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $ruta);
        $partes = explode(DIRECTORY_SEPARATOR, $ruta);
        $absoluta = [];
        foreach ($partes as $parte) {
            if ('.' == $parte) continue;
            if ('..' == $parte) {
                array_pop($absoluta);
            } else {
                $absoluta[] = $parte;
            }
        }
        return implode(DIRECTORY_SEPARATOR, $absoluta);
    }

function err($code,$msg) {
	http_response_code($code);
	header("Content-Type: application/json");
	echo json_encode(['error' => ['code'=>intval($code), 'msg' => $msg]]);
	exit;
}

function asBytes($ini_v) {
	$ini_v = trim($ini_v);
	$s = ['g'=> 1<<30, 'm' => 1<<20, 'k' => 1<<10];
	return intval($ini_v) * ($s[strtolower(substr($ini_v,-1))] ?: 1);
}
$MAX_UPLOAD_SIZE = min(asBytes(ini_get('post_max_size')), asBytes(ini_get('upload_max_filesize')));
?>
<!DOCTYPE html>
<html><head>
<meta http-equiv="content-type" content="text/html; charset=utf-8">

<style>
body {font-family: "lucida grande","Segoe UI",Arial, sans-serif; font-size: 14px;width:1024;padding:1em;margin:0;}
th {font-weight: normal; color: #FFFFFF; background-color: #005A9E; padding:.5em 1em .5em .2em;
	text-align: left;cursor:pointer;user-select: none;}
th .indicator {margin-left: 6px }
thead {border-top: 1px solid #82CFFA; border-bottom: 1px solid #96C4EA;border-left: 1px solid #E7F2FB;
	border-right: 1px solid #E7F2FB; }
.tools{border: 0px;}
#top {height:52px;float: left;}
#mkdir {display:inline-block;float:left;}
label { display:block; font-size:11px; color:#555;}
#upload_progress {padding: 4px 0;}
#upload_progress .error {color:#a00;}
#upload_progress > div { padding:3px 0;}
.no_write #mkdir, .no_write #file_drop_target {display: none}
.progress_track {display:inline-block;width:200px;height:10px;border:1px solid #333;margin: 0 4px 0 10px;}
.progress {background-color: #82CFFA;height:10px; }
footer {font-size:11px; color:#bbbbc5; padding:4em 0 0;text-align: left;}
footer a, footer a:visited {color:#bbbbc5;}
#breadcrumb { padding-top:34px; font-size:15px; color:#aaa;display:inline-block;float:left;}
#folder_actions {width: 50%;float:right;}
a, a:visited { color:#00c; text-decoration: none}
a:hover {text-decoration: underline}
.sort_hide{ display:none;}
table {border-collapse: collapse;width:100%;}
thead {max-width: 1024px}
td { padding:.2em 1em .2em .2em; border-bottom:1px solid #def;height:30px; font-size:12px;white-space: nowrap;}
td.first {font-size:14px;white-space: normal;}
td.empty { color:#777; font-style: italic; text-align: center;padding:3em 0;}
.is_dir .size {color:transparent;font-size:0;}
.is_dir .size:before {content: "--"; font-size:14px;color:#333;}
.is_dir .download{visibility: hidden}
a.inicio {
	display:inline-block;
	background: url(.img/inicio.png) no-repeat scroll 0px 0px;
	background-size: 40%;
	color: #000;
	margin-left: 10px;font-size:14px;padding:4px 0px 4px 25px;
}
a.delete {
	display:inline-block;
	background: url(.img/delete.png) no-repeat scroll 0px 0px;
	background-size: 35%;
	color: #000;
	margin-left: 10px;font-size:11px;padding:4px 0px 4px 25px;
}
.name {
	background: url(.img/archivo.png) no-repeat scroll 0px 12px;
	background-size: 25%;
	padding:15px 0 10px 30px;
}
.is_dir .name {
	background: url(.img/carpeta.png) no-repeat scroll 0px 10px;
	background-size: 40%;
	padding:15px 10px 10px 40px;
}
.download {
	background: url(.img/descargar.png) no-repeat scroll 0px 0px;
	background-size: 25%;
	color: #000;
	margin-left: 10px;padding:4px 0 4px 25px;
}
.logo{
	display: flex;
    align-items: center ;
    justify-content: center;
}
</style>
<script src="//ajax.googleapis.com/ajax/libs/jquery/1.8.2/jquery.min.js"></script>
<script>
(function($){
	$.fn.tablesorter = function() {
		var $table = this;
		this.find('th').click(function() {
			var idx = $(this).index();
			var direction = $(this).hasClass('sort_asc');
			$table.tablesortby(idx,direction);
		});
		return this;
	};
	$.fn.tablesortby = function(idx,direction) {
		var $rows = this.find('tbody tr');
		function elementToVal(a) {
			var $a_elem = $(a).find('td:nth-child('+(idx+1)+')');
			var a_val = $a_elem.attr('data-sort') || $a_elem.text();
			return (a_val == parseInt(a_val) ? parseInt(a_val) : a_val);
		}
		$rows.sort(function(a,b){
			var a_val = elementToVal(a), b_val = elementToVal(b);
			return (a_val > b_val ? 1 : (a_val == b_val ? 0 : -1)) * (direction ? 1 : -1);
		})
		this.find('th').removeClass('sort_asc sort_desc');
		$(this).find('thead th:nth-child('+(idx+1)+')').addClass(direction ? 'sort_desc' : 'sort_asc');
		for(var i =0;i<$rows.length;i++)
			this.append($rows[i]);
		this.settablesortmarkers();
		return this;
	}
	$.fn.retablesort = function() {
		var $e = this.find('thead th.sort_asc, thead th.sort_desc');
		if($e.length)
			this.tablesortby($e.index(), $e.hasClass('sort_desc') );

		return this;
	}
	$.fn.settablesortmarkers = function() {
		this.find('thead th span.indicator').remove();
		this.find('thead th.sort_asc').append('<span class="indicator">&darr;<span>');
		this.find('thead th.sort_desc').append('<span class="indicator">&uarr;<span>');
		return this;
	}
})(jQuery);
$(function(){
	var XSRF = (document.cookie.match('(^|; )_sfm_xsrf=([^;]*)')||0)[2];
	var MAX_UPLOAD_SIZE = <?php echo $MAX_UPLOAD_SIZE ?>;
	var $tbody = $('#list');
	$(window).on('hashchange',list).trigger('hashchange');
	$('#table').tablesorter();

	$('#table').on('click','.delete',function(data) {
		$.post("",{'do':'delete',file:$(this).attr('data-file'),xsrf:XSRF},function(response){
			list();
		},'json');
		return false;
	});

	$('#mkdir').submit(function(e) {
		var hashval = decodeURIComponent(window.location.hash.substr(1)),
			$dir = $(this).find('[name=name]');
		e.preventDefault();
		$dir.val().length && $.post('?',{'do':'mkdir',name:$dir.val(),xsrf:XSRF,file:hashval},function(data){
			list();
		},'json');
		$dir.val('');
		return false;
	});
<?php if($permitir_upload): ?>
	// file upload stuff
	$('#file_drop_target').on('dragover',function(){
		$(this).addClass('drag_over');
		return false;
	}).on('dragend',function(){
		$(this).removeClass('drag_over');
		return false;
	}).on('drop',function(e){
		e.preventDefault();
		var files = e.originalEvent.dataTransfer.files;
		$.each(files,function(k,file) {
			uploadFile(file);
		});
		$(this).removeClass('drag_over');
	});
	$('input[type=file]').change(function(e) {
		e.preventDefault();
		$.each(this.files,function(k,file) {
			uploadFile(file);
		});
	});


	function uploadFile(file) {
		var folder = decodeURIComponent(window.location.hash.substr(1));

		if(file.size > MAX_UPLOAD_SIZE) {
			var $error_row = renderFileSizeErrorRow(file,folder);
			$('#upload_progress').append($error_row);
			window.setTimeout(function(){$error_row.fadeOut();},5000);
			return false;
		}

		var $row = renderFileUploadRow(file,folder);
		$('#upload_progress').append($row);
		var fd = new FormData();
		fd.append('file_data',file);
		fd.append('file',folder);
		fd.append('xsrf',XSRF);
		fd.append('do','upload');
		var xhr = new XMLHttpRequest();
		xhr.open('POST', '?');
		xhr.onload = function() {
			$row.remove();
    		list();
  		};
		xhr.upload.onprogress = function(e){
			if(e.lengthComputable) {
				$row.find('.progress').css('width',(e.loaded/e.total*100 | 0)+'%' );
			}
		};
	    xhr.send(fd);
	}
	function renderFileUploadRow(file,folder) {
		return $row = $('<div/>')
			.append( $('<span class="fileuploadname" />').text( (folder ? folder+'/':'')+file.name))
			.append( $('<div class="progress_track"><div class="progress"></div></div>')  )
			.append( $('<span class="size" />').text(formatFileSize(file.size)) )
	};
	function renderFileSizeErrorRow(file,folder) {
		return $row = $('<div class="error" />')
			.append( $('<span class="fileuploadname" />').text( 'Error: ' + (folder ? folder+'/':'')+file.name))
			.append( $('<span/>').html(' tamaño - <b>' + formatFileSize(file.size) + '</b>'
				+' excede el tamaño máximo de <b>' + formatFileSize(MAX_UPLOAD_SIZE) + '</b>')  );
	}
<?php endif; ?>
	function list() {
		var hashval = window.location.hash.substr(1);
		$.get('?do=list&file='+ hashval,function(data) {
			$tbody.empty();
			$('#breadcrumb').empty().html(renderBreadcrumbs(hashval));
			if(data.success) {
				$.each(data.results,function(k,v){
					$tbody.append(renderFileRow(v));
				});
				!data.results.length && $tbody.append('<tr><td class="empty" colspan=5>Esta carpeta está vacía</td></tr>')
				data.is_writable ? $('body').removeClass('no_write') : $('body').addClass('no_write');
			} else {
				console.warn(data.error.msg);
			}
			$('#table').retablesort();
		},'json');
	}
	function renderFileRow(data) {
		var $link = $('<a class="name" />')
			.attr('href', data.is_dir ? '#' + encodeURIComponent(data.path) : './' + data.path)
			.text(data.name);
		var allow_direct_link = <?php echo $permitir_link_directo?'true':'false'; ?>;
        	if (!data.is_dir && !allow_direct_link)  $link.css('pointer-events','none');
		var $dl_link = $('<a/>').attr('href','?do=download&file='+ encodeURIComponent(data.path))
			.addClass('download').text('Descargar');
		var $delete_link = $('<a href="#" />').attr('data-file',data.path).addClass('delete').text('Borrar');
		var perms = [];
		if(data.is_readable) perms.push('lectura');
		if(data.is_writable) perms.push('escritura');
		if(data.is_executable) perms.push('ejecutar');
		var $html = $('<tr />')
			.addClass(data.is_dir ? 'is_dir' : '')
			.append( $('<td class="first" />').append($link) )
			.append( $('<td/>').attr('data-sort',data.is_dir ? -1 : data.size)
				.html($('<span class="size" />').text(formatFileSize(data.size))) )
			.append( $('<td/>').attr('data-sort',data.mtime).text(formatTimestamp(data.mtime)) )
			.append( $('<td/>').text(perms.join('+')) )
			.append( $('<td/>').append($dl_link).append( data.is_deleteable ? $delete_link : '') )
		return $html;
	}
	function renderBreadcrumbs(path) {
		var base = "",
			$html = $('<div/>').append( $('<a href=#>Inicio</a></div>') );
		$.each(path.split('%2F'),function(k,v){
			if(v) {
				var v_as_text = decodeURIComponent(v);
				$html.append( $('<span/>').text(' ▸ ') )
					.append( $('<a/>').attr('href','#'+base+v).text(v_as_text) );
				base += v + '%2F';
			}
		});
		return $html;
	}
	function formatTimestamp(unix_timestamp) {
		var m = ['Ene', 'Feb', 'Mar', 'Abr', 'May', 'Jun', 'Jul', 'Ago', 'Sep', 'Oct', 'Nov', 'Dec'];
		var d = new Date(unix_timestamp*1000);
		return [m[d.getMonth()],' ',d.getDate(),', ',d.getFullYear()," ",
			(d.getHours() % 12 || 12),":",(d.getMinutes() < 10 ? '0' : '')+d.getMinutes(),
			" ",d.getHours() >= 12 ? 'PM' : 'AM'].join('');
	}
	function formatFileSize(bytes) {
		var s = ['bytes', 'KB','MB','GB','TB','PB','EB'];
		for(var pos = 0;bytes >= 1000; pos++,bytes /= 1024);
		var d = Math.round(bytes*10);
		return pos ? [parseInt(d/10),".",d%10," ",s[pos]].join('') : bytes + ' bytes';
	}
})

</script>
</head><body>

<table>
<tbody>
<tr>
<td class="tools"><a class="inicio" href=#>Inicio</a></td>
<td class="tools">&nbsp;</td>
<td class="tools" rowspan="3"><img src="/.img/logo.png" width="140" height="100" alt="Logo"></td>
</tr>
<tr>
<td class="tools">
	<?php if($permitir_crear_carpeta): ?>
	<form action="?" method="post" id="mkdir" />
		<input placeholder="Ingrese nombre directorio" id=dirname type=text name=name value="" />
		<input type="submit" value="Crear" />
	</form>
   <?php endif; ?>
</td>
<td class="tools">&nbsp;</td>
</tr>
<tr>
<td class="tools">
	<?php if($permitir_upload): ?>
	<div id="file_drop_target">
		<input type="file" multiple />
	</div>
	<?php endif; ?>
</td>
<td class="tools">&nbsp;</td>
</tr>
</tbody>
</table>



<div id="top">
	<div id="breadcrumb">&nbsp;</div>
</div>

<div id="upload_progress"></div>
<table id="table"><thead><tr>
	<th>Nombre</th>
	<th>Tamaño</th>
	<th>Modificado</th>
	<th>Permisos</th>
	<th>Acciones</th>
</tr></thead><tbody id="list">

</tbody></table>
<footer>Seminario de Sistemas Colaborativos - Sharepoint - <a href="https://github.com/yamilapandolfini">link</a></footer>
</body></html>