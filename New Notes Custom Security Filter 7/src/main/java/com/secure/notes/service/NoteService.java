package com.secure.notes.service;

import com.secure.notes.model.Note;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface NoteService {
    Note createNoteForUser(String username,String content);
    Note updateNoteForUser(Long noteId,String content,String username);
    void deleteNoteForUser(Long noteId,String username);
    List<Note> getNotesForUser(String username);
}
