import PropTypes from "prop-types";

const PageTitle = ({ subTitle, title, classOption }) => {
    return (
        <div className={`page-title-content ${classOption}`}>
            <h4 className="page-title">{subTitle}</h4>
            <h2 className="title">{title}</h2>
        </div>
    );
};

PageTitle.propTypes = {
    subTitle: PropTypes.string,
    title: PropTypes.string,
    classOption: PropTypes.string,
};
PageTitle.defaultProps = {
    classOption: "content-style2 text-center",
};

export default PageTitle;
