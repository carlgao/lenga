;;; mh-comp-frame.el --- Message composition in a separate frame
;;
;; Copyright (C) 2002 Satyaki Das
 
;; Authors:   Satyaki Das <satyaki@theforce.stanford.edu>
;; Created:   17 Dec 2002
;; Version:   1.0 (17 Dec 2002)
;; Keywords:  mh-e, mail, emacs, xemacs

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation; either version 2, or (at your option)
;; any later version.
;; 
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;; 
;; You should have received a copy of the GNU General Public License
;; along with this program; if not, write to the Free Software
;; Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

;;; Commentary:

;; If this file is loaded into emacs then commands like mh-send, mh-reply,
;; mh-forward etc. will create a new frame in which the draft is opened. When
;; the mail is sent (or the draft deleted) this frame goes away. This means
;; that I can continue visiting other messages or folders or read new mail in
;; the original frame. It works best when mh-delete-yanked-msg-window-flag is
;; nil.

;; To enable this, drop the file into a directory that is in the load-path and
;; add:
;;  (require 'mh-comp-frame)
;; to the .emacs.

;;; Code:

(defvar mh-delete-mail-frame-flag nil
  "Non-nil means the mail composition frame is to be deleted.")

;; Frame creation advice...
(defmacro mh-advise-mh-frame-creation (func)
  "Advise FUNC to create new frames during MH message composition."
  `(defadvice ,func (around mh-new-frame activate)
     "Compose message in new frame."
     (select-frame (make-frame))
     (prog1 ad-do-it
       (set (make-variable-buffer-local 'mh-delete-mail-frame-flag) t)
       (delete-other-windows))))

;; Frame deletion advice...
(defmacro mh-advise-mh-frame-deletion (func)
  "Advise FUNC to delete frame after execution."
  `(defadvice ,func (around mh-delete-frame activate)
     "Delete frame if the draft buffer doesn't exist anymore."
     (let ((buffer-name (buffer-name))
           (delete-frame-flag mh-delete-mail-frame-flag))
       (prog1 ad-do-it
         (when (and delete-frame-flag (not (equal (buffer-name) buffer-name)))
           (delete-frame))))))

;; Advise the appropriate functions...
(mh-advise-mh-frame-creation mh-send)
(mh-advise-mh-frame-creation mh-reply)
(mh-advise-mh-frame-creation mh-forward)
(mh-advise-mh-frame-creation mh-edit-again)
(mh-advise-mh-frame-creation mh-extract-rejected-mail)
(mh-advise-mh-frame-deletion mh-send-letter)
(mh-advise-mh-frame-deletion mh-fully-kill-draft)

(provide 'mh-comp-frame)

;;; Local Variables:
;;; indent-tabs-mode: nil
;;; sentence-end-double-space: nil
;;; End:

;;; mh-comp-frame.el ends here
