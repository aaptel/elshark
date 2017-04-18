;;; elshark.el --- An Emacs frontend for Wireshark

;; Copyright (C) 2017 Aurélien Aptel <aurelien.aptel@gmail.com>

;; Author: Aurélien Aptel <aurelien.aptel@gmail.com>
;; Maintainer: Aurélien Aptel <aurelien.aptel@gmail.com>

;; Package-Requires: ((emacs "24.4") (dash "2.10.0"))
;; Keywords: comm net wireshark
;; Homepage: https://github.com/aaptel/elshark

;; Elshark requires at least GNU Emacs 24.4

;; Elshark is free software; you can redistribute it and/or modify it
;; under the terms of the GNU General Public License as published by
;; the Free Software Foundation; either version 3, or (at your option)
;; any later version.
;;
;; Elshark is distributed in the hope that it will be useful, but WITHOUT
;; ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
;; or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
;; License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with Elshark.  If not, see http://www.gnu.org/licenses.

;;; Commentary:

;;; Code:

(defvar-local elshark-buffer-cap nil
  "Current buffer elshark-cap instance")

(defvar elshark-detail-window nil)

(defun elshark--dump-field (f indent)
  (when f
    (dotimes (i indent) (insert "    "))
    (insert (or (alist-get 'showname (cadr f)) "") "\n")
    (dolist (c (cddr f))
      (elshark--dump-field c (1+ indent)))))

(defun elshark-dump-packet (data)
  (dolist (p (cddr (caddr (cadddr data))))
    (insert (or (alist-get 'showname (cadr p)) "") "\n")
    (dolist (f (cddr p))
      (elshark--dump-field f 1))))

(defun elshark-get-proto (data proto)
  (cl-loop for p in (cddr (caddr (cadddr data)))
	   if (string= (alist-get 'name (cadr p)) proto)
	   return (cddr p)))

(defun elshark-get-field (data field)
  (cl-loop for f in data
	   if (string= (alist-get 'name (cadr f)) field)
	   return (cadr f)))

(defun elshark-popup-detail (&optional no)
  (interactive)
  (when (not no)
    (setq no
	  (save-excursion
	    (beginning-of-line)
	    (if (looking-at (rx (group (+ digit))))
		(string-to-number (match-string 1))
	      (error "Cannot find a packet number in current line")))))

  (let ((bufname (format "*capture %s packet %d*" (oref elshark-buffer-cap fn) no))
	(data (elshark-cap--read-detail elshark-buffer-cap no)))

    ;; create window if we dont have one
    (when (or (not elshark-detail-window) (not (window-live-p elshark-detail-window)))
      (setq elshark-detail-window (split-window-below)))

    ;; select it
    (select-window elshark-detail-window)

    ;; set the buffer its displaying
    (when (get-buffer bufname)
      (kill-buffer bufname))
    (switch-to-buffer (get-buffer-create bufname))
    (elshark-detail-mode)

    ;; insert packet details
    (let ((inhibit-read-only t))
      (elshark-dump-packet data))
    (goto-char (point-min))))


(defun elshark-find-file (fn)
  (interactive "fCapture file: ")
  (let ((bufname (format "*capture %s*" fn))
	(cap (elshark-cap :filename fn)))
    (when (get-buffer bufname)
      (kill-buffer bufname))
    (switch-to-buffer (get-buffer-create bufname))
    (elshark-mode)
    (setq elshark-buffer-cap cap)
    (elshark-cap--read-summary cap)
    (let ((inhibit-read-only t))
      (elshark-cap--insert-summary cap))
    (goto-char (point-min))))


(defvar elshark-mode-map
  (let ((map (make-sparse-keymap)))
    (suppress-keymap map)
    (define-key map (kbd "d") #'elshark-popup-detail)
    map))

(define-derived-mode elshark-mode special-mode "elshark mode"
  "Major mode for displaying network traces

\\{elshark-mode-map}"
  (buffer-disable-undo))

(defvar elshark-detail-mode-map
  (let ((map (make-sparse-keymap)))
    (suppress-keymap map)
    ;; TODO: add details kb
    map))

(define-derived-mode elshark-detail-mode special-mode "elshark detail mode"
  "Major mode for displaying network traces packet details

\\{elshark-detail-mode-map}"
  (buffer-disable-undo))

(defclass elshark-cap ()
  ((fn
    :initarg :filename
    :type string
    :documentation "capture file name")
   (summ
    :type list
    :documentation "summary lines"))
  "Network capture instance")

(defmethod elshark-cap--read-summary ((cap elshark-cap))
  (oset cap summ
	(with-temp-buffer
	  (insert (shell-command-to-string
		   (format "tshark -r %s -T psml"
			   (shell-quote-argument (expand-file-name (oref cap fn))))))
	  (libxml-parse-xml-region (point-min) (point-max)))))

(defmethod elshark-cap--read-detail ((cap elshark-cap) frame)
  "Dissect frame number FRAME for the capture CAP"
  (with-temp-buffer
    (insert (shell-command-to-string (format
				      "tshark -r %s -Y 'frame.number == %d' -T pdml"
				      (shell-quote-argument (expand-file-name (oref cap fn))) frame)))
    (libxml-parse-xml-region (point-min) (point-max))))

(defmethod elshark-cap--insert-summary ((cap elshark-cap))
  (dolist (e (cddr (oref cap summ)))
    (when (eq (car e) 'packet)
      (let ((p-no    (caddr (elt e 2)))
	    (p-t     (caddr (elt e 3)))
	    (p-src   (caddr (elt e 4)))
	    (p-dst   (caddr (elt e 5)))
	    (p-proto (caddr (elt e 6)))
	    (p-len   (caddr (elt e 7)))
	    (p-info  (caddr (elt e 8))))
	(insert (format "%s %s %s %s %s %s %s\n" p-no p-t p-src p-dst p-proto p-len p-info))))))

(provide 'elshark)

;;; elshark.el ends here
