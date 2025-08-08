import PropTypes from "prop-types";

const ContactInfo = ({ data }) => {
    return (
        <div
            className="info-item info-item2"
            data-aos="fade-up"
            data-aos-delay={data.delay}
        >
            <div className="info-title">
                <h4>{data.title}</h4>
                <div className="icon">
                    <i className={data.icon}></i>
                </div>
            </div>
            <div
                className="info-content"
                dangerouslySetInnerHTML={{ __html: data.info }}
            />
        </div>
    );
};

ContactInfo.propTypes = {
    data: PropTypes.object,
};

export default ContactInfo;
