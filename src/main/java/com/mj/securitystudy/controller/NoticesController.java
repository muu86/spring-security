package com.mj.securitystudy.controller;

import com.mj.securitystudy.model.Notice;
import com.mj.securitystudy.repository.NoticeRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class NoticesController {

	private final NoticeRepository noticeRepository;

	@GetMapping("/notices")
	public List<Notice> getNotices(String input) {
		List<Notice> notices = noticeRepository.findAllActiveNotices();
		return notices;
	}
}
