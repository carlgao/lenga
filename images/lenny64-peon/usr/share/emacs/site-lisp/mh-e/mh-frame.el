;;; mh-frame.el --- Open MH-E in a separate frame
;;
;; Copyright (C) 1995 Mark Crimmins
;; Copyright (C) 1995, 2001, 2002 Eric Ding
 
;; Authors:   Eric Ding <ericding@alum.mit.edu>, Mark Crimmins
;; Created:   20 Dec 1995
;; Version:   1.1 (13 Nov 2002)
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

;; This code is based on mh-e-in-frame.el, originally written by Mark
;; Crimmins.  The latest version of mh-frame.el can be found at
;; http://cvs.sourceforge.net/cgi-bin/viewcvs.cgi/mh-e/contrib/mh-frame.el

;;; Description:

;; Visit (or, if necessary, open) a frame called "MH-E" for mh-rmail,
;; rescan folder and show current message.  On mh-quit from +inbox in
;; MH-E frame, delete that frame, and if there's a pid argument
;; argument, kill the proc with that pid (see shell script below).
;;
;; To use mh-frame in emacs, add the following line to your .emacs file:
;;
;;	(autoload 'mh-frame "mh-frame" "" t)
;;
;; You can then start up MH-E in a separate frame with
;;
;;	M-x mh-frame
;;
;; or you could bind a key to this function:
;;
;;      (global-set-key "\C-x\r" 'mh-frame)
;;
;; This elisp code was originally designed to be used with a shell script
;; that calls it via the gnuserv package, which is included in XEmacs, but
;; not in GNU Emacs (YMMV).  To use it with GNU emacs, you'll need to install
;; gnuserv yourself.  At the time of the writing of this paragraph, you could
;; find gnuserv 3.12.4 at
;;
;; 	http://meltin.net/hacks/emacs/

;; #!/bin/sh
;; # MH-E: launch an MH-E session in emacs on xwindows
;; 
;; exec 2> /dev/null
;; if (gnudoit < /dev/null) ; then
;;   true
;; else
;;   if xmessage -buttons Yes:0,Cancel:1 "No emacs running gnuserv.
;;     Start emacs?" -default Yes
;;   then
;;     (emacs &)
;;     until (exec gnudoit < /dev/null)
;;     do sleep 3
;;     done
;;   fi
;; fi > /dev/null
;; 
;; # this is approximately 277 hours
;; sleep 1000000 &
;; 
;; # tell emacs what to do and the pid of our sleep process
;; gnudoit -q "(require 'mh-frame)
;; (mh-frame $!)" &
;;
;; # We become a zombie until the sleep process is killed
;; exit

;; ----------------------------------------------------------------------------
;;; Change log:
;; 2002-11-13  Mark D. Baushke <mdb@gnu.org>
;;  (mh-frame-sh-pid): new defvar for this variable.
;;  (mh-frame-delete-frame-now-flag): renamed from
;;  mh-frame-delete-frame-now.
;;  (mh-fame): use it. checkdoc fix.
;;  (mh-frame-mh-quit-hook, mh-frame-kill-emacs-hook,
;;  mh-frame-get-mh-frame, mh-quit): checkdoc fix.
;;  Added RCS Id line to aid in bug reports.
;;  This file is now at release 1.1 due to a variable name change.
;;
;; 2001-12-07  Eric Ding  <ericding@alum.mit.edu>
;;  (mh-frame): use make-frame instead of new-frame (deprecated, temp alias)
;;
;; 2001-11-30  Eric Ding  <ericding@alum.mit.edu>
;;  (mh-frame): rename get-mh-e-frame to mh-frame-get-mh-frame and move
;;  definition out of mh-frame.
;;
;; 2001-11-30  Eric Ding  <ericding@alum.mit.edu>
;;  rename package to mh-frame
;;
;; Thu Nov 29 09:48:32 2001  Eric Ding  <ericding@alum.mit.edu>
;;  define frame-name if it's unbound, rather than checking for xemacs
;;  release as frame-mh-e 1.0
;;
;; Wed Nov 28 15:47:05 2001  Eric Ding  <ericding@alum.mit.edu>
;;  use eval-after-load rather than (require 'mh-e)
;;
;; Fri Dec 22 13:58:59 1995  Eric Ding  <ericding@alum.mit.edu>
;;  added using-xemacs variable
;;  added (require 'mh-e)
;;  changed naming from mh-* to frame-mh-e-*
;;  conditionalized the frame-title-format change in frame-mh-e
;;  added confirmation for mh-quit
;;  added explicit defuns for hooks
;;  changed (add-to-list features...) to (provide 'frame-mh-e)
;;
;; Fri Dec 22 15:17:12 1995  Eric Ding  <ericding@alum.mit.edu>
;;  changed string-match/eq to equal where appropriate
;;
;; Jan 2 1995 Mark Crimmins
;;  ask for quit confirmation only if buffer name is "+inbox".
;; ----------------------------------------------------------------------------
;;; Code:

;;; define frame-name if needed (currently only defined in XEmacs)
(if (not (fboundp 'frame-name))
    (defun frame-name (&optional FRAME)
      (let ((params (frame-parameters FRAME))
            frame-name)
        (while (consp params)
          (let ((elt (car params)))
            (if (eq (car elt) 'name)
                (setq frame-name (cdr elt))))
          (setq params (cdr params)))
        frame-name)))

(defvar mh-frame-sh-pid nil
  "Variable to hold the PID of the MH-E frmae if it is running.")

(defvar mh-frame-delete-frame-now-flag nil
  "Non-nil means that the MH-E frame should be killed.")

(defun mh-frame (&optional pid)
  "Open MH-E in a new frame.
Optional argument PID is saved to later be able to kill the frame."
  (interactive)
  (let (f)
    (cond ((setq f (mh-frame-get-mh-frame))
	   (raise-frame f))
	  (t
	   (setq f (make-frame '((name . "MH-E"))))))
    (select-frame f))
  (mh-rmail)
  (mh-rescan-folder)
  (mh-show)
  (setq mh-frame-sh-pid pid))

(defun mh-frame-get-mh-frame ()
  "Look in the `frame-list' for the MH-E frame."
  (let (a (l (frame-list)))
    (while l
      (if (equal "MH-E" (frame-name (car l)))
	  (setq a (car l)))
      (setq l (cdr l)))
    a))

(eval-after-load "mh-e"
  '(progn
     (if (not (fboundp 'mh-frame/original-mh-quit))
	 (fset 'mh-frame/original-mh-quit
	       (symbol-function 'mh-quit)))
     (defun mh-quit ()
       "Restore the previous window configuration, if one exists.
If run from the +inbox buffer, query to delete the MH-E frame before
calling the real \\[mh-frame/original-mh-quit] function."
       (interactive)
       (if (equal (buffer-name (current-buffer)) mh-inbox)
	   (cond ((y-or-n-p "Quit MH-E? ")
		  (setq mh-frame-delete-frame-now-flag t)
		  (mh-frame/original-mh-quit))
		 (t (message nil)))
	 (mh-frame/original-mh-quit)))
     ))

(defun mh-frame-mh-quit-hook ()
  "Hook to terminate the MH-E frame if one exists."
  (cond (mh-frame-delete-frame-now-flag
	 (delete-frame)
	 (if mh-frame-sh-pid
	     (shell-command (concat "kill -9 " mh-frame-sh-pid)))
	 (setq mh-frame-sh-pid nil)
	 (setq mh-frame-delete-frame-now-flag nil))))

(add-hook 'mh-quit-hook 'mh-frame-mh-quit-hook)

(defun mh-frame-kill-emacs-hook ()
  "Hook to kille the MH-E frame process if one exists."
  (if mh-frame-sh-pid
      (shell-command (concat "kill -9 " mh-frame-sh-pid))))

(add-hook 'kill-emacs-hook 'mh-frame-kill-emacs-hook)

(setq mh-frame-delete-frame-now-flag nil)
(setq mh-frame-sh-pid nil)

(provide 'mh-frame)

;;; Local Variables:
;;; indent-tabs-mode: nil
;;; sentence-end-double-space: nil
;;; End:

;;; mh-frame.el ends here
