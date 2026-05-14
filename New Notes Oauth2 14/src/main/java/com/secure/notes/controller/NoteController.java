package com.secure.notes.controller;

import com.secure.notes.model.Note;
import com.secure.notes.service.NoteService;
import org.hibernate.annotations.SortComparator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/notes")
public class NoteController {
    @Autowired
    private NoteService noteService;


    //here user details gives the info who is the user logged in
    //authenticationPrincipal is used to get the info to the controller who is logged in rightnow
    @PostMapping
    public Note createNote(@RequestBody String content, @AuthenticationPrincipal UserDetails userDetails){
        String username= userDetails.getUsername();
        return noteService.createNoteForUser(username,content);
    }

    @GetMapping
    public List<Note> getUserNotes(@AuthenticationPrincipal UserDetails userDetails){
        String username= userDetails.getUsername();
        return noteService.getNotesForUser(username);
    }

    @PutMapping("/{noteId}")
    public Note updateNote(@PathVariable Long noteId,@RequestBody String content, @AuthenticationPrincipal UserDetails userDetails){
        String username= userDetails.getUsername();
        return noteService.updateNoteForUser(noteId,content,username);
    }

    @DeleteMapping("/{noteId}")
    public void deleteNote(@PathVariable Long noteId, @AuthenticationPrincipal UserDetails userDetails){
        String username= userDetails.getUsername();
        noteService.deleteNoteForUser(noteId,username);
    }
}
