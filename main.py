from selenium import webdriver
import time
import re
import codecs
import winsound
from urllib.parse import urljoin
from selenium.common.exceptions import NoSuchElementException, StaleElementReferenceException

BASE_URL_ANYRUN = 'https://app.any.run/submissions/'
PATH_DRIVER = r'.\\driver\\msedgedriver.exe'
malicious_activities = []


def get_month(index):
    switch_case = {
        1: 'January',
        2: 'February',
        3: 'March',
        4: 'April',
        5: 'May',
        6: 'June',
        7: 'July',
        8: 'August',
        9: 'September',
        10: 'October',
        11: 'November',
        12: 'December'
    }
    return switch_case.get(index, 'Nope')


def crawl_data():
    previous_month = 0
    # input the month to get data
    while True:
        selection = input('Input the month you want to crawl info: ')
        month = get_month(int(selection))
        if selection == 'Nope':
            continue
        else:
            previous_month = 'December' if month == 'January' else get_month(int(selection) - 1)
            break
    selenium = webdriver.Edge(PATH_DRIVER, {})
    selenium.maximize_window()
    selenium.get(BASE_URL_ANYRUN)
    file = codecs.open('.\\data.txt', mode='a', encoding='utf-8')
    while True:
        # Input email and password to login
        try:
            login_button = selenium.find_element_by_class_name('login-toggle')
            login_button.click()
            time.sleep(2)
            email = input('Input your email: ')
            password = input('input your password: ')
            input_email = selenium.find_element_by_id('at-field-username_and_email')
            input_password = selenium.find_element_by_id('at-field-password')
            input_email.send_keys(email)
            input_password.send_keys(password)
            button_submit = selenium.find_element_by_css_selector('.at-btn.submit.btn.btn-signin')
            button_submit.click()
            break
        except NoSuchElementException:
            time.sleep(1)
            continue
    while True:
        time.sleep(2)
        while True:
            # Check captcha and page have got data
            try:
                if selenium.find_element_by_css_selector(
                        'div.public-tasks-captcha').is_displayed() or selenium.find_element_by_css_selector(
                        'div.public-tasks-modal_content').is_displayed():
                    winsound.PlaySound('C:\\Windows\\Media\\Windows Exclamation.wav', winsound.SND_FILENAME)
                    input('You must check captcha to continue, then press any key and Enter to continue: ')
                    continue
            except NoSuchElementException:
                source_page = selenium.page_source
                flag_content_1 = re.search('No threats detected', source_page)
                flag_content_2 = re.search('Suspicious activity', source_page)
                flag_content_3 = re.search('Malicious activity', source_page)
                if flag_content_1 is not None or flag_content_2 is not None or flag_content_3 is not None: break
        # Parse data
        try:
            rows = selenium.find_elements_by_css_selector('.history-table--content__row')
            for item in rows:
                if str(item.find_element_by_css_selector(
                        'a .history__os .os__description .os__info .os__time').text).find(month) != -1:
                    if item.find_element_by_css_selector(
                            'a .history__object .object__wrap .top .verdict__threat').text == 'Malicious activity' or item.find_element_by_css_selector(
                            'a .history__object .object__wrap .top .verdict__threat').text == 'Suspicious activity':
                        name = item.find_element_by_css_selector(
                            'a .history__object .object__wrap .top .top-right .object__name').text
                        hash_md5 = item.find_element_by_css_selector('a .history__hash .hash__item .hash__value').text
                        sub_link = item.find_element_by_css_selector('a').get_attribute('href')
                        if hash_md5 not in malicious_activities:
                            malicious_activities.append(hash_md5)
                            link = urljoin(BASE_URL_ANYRUN, sub_link)
                            line = f'{name}\n{link}\n\n'
                            file.write(line)
                elif str(item.find_element_by_css_selector('a .history__os .os__description .os__info .os__time').text).find(previous_month) != -1:
                    file.close()
                    selenium.quit()
                    exit(0)
        except StaleElementReferenceException:
            continue
        # Click next button
        try:
            if selenium.find_element_by_css_selector('.public-tasks-modal.ANONYMOUS').is_displayed() or selenium.find_element_by_class_name('public-tasks-modal_content').is_displayed():
                winsound.PlaySound('C:\\Windows\\Media\\Windows Exclamation.wav', winsound.SND_FILENAME)
                input('You must login to continue, then press any key and Enter to continue: ')
                continue
        except NoSuchElementException:
            next_button = selenium.find_element_by_class_name('history-table--footer__next')
            next_button.click()


if __name__ == '__main__':
    crawl_data()
