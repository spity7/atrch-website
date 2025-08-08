import PropTypes from "prop-types";
import PageTitle from "../../../components/page-title";

const PageTitleContainerTwo = ({ title, subTitle }) => {
    return (
        <div className="page-title-area">
            <div className="container">
                <div className="row">
                    <div className="col-lg-12 text-center" data-aos="fade-up">
                        <PageTitle
                            classOption="page-title-content"
                            subTitle={subTitle}
                            title={title}
                        />
                    </div>
                </div>
            </div>
        </div>
    );
};

PageTitleContainerTwo.propTypes = {
    subTitle: PropTypes.string,
    title: PropTypes.string,
};

export default PageTitleContainerTwo;
